package tunfe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// handleTCP accepts one forwarded TCP connection from the netstack.
//
// gVisor already calls this on a goroutine of its own, but that goroutine has
// no recover barrier: a panic on it takes the process down and strands the
// capture routes pointing at a device nothing is reading. The work therefore
// moves onto a flow.Safe goroutine, which is also what makes shutdown able to
// wait for live flows.
func (s *Server) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst, dok := addrPortOf(id.LocalAddress, id.LocalPort)
	src, _ := addrPortOf(id.RemoteAddress, id.RemotePort)
	if !dok {
		// No usable destination: answer with a reset rather than leaving the
		// client's SYN unanswered, which would cost it a full connect timeout.
		s.refused.Add(1)
		r.Complete(true)
		return
	}
	if !s.track("tunfe/tcp", func() { s.serveTCP(r, dst, src) }) {
		// The datapath has drained: this SYN arrived after shutdown began. It
		// is reset for the same reason an unusable destination is — an
		// unanswered SYN costs the client a full connect timeout — and the
		// request must be completed either way, because it owns the half-open
		// entry the forwarder is holding.
		s.refused.Add(1)
		r.Complete(true)
		return
	}
	s.tcpFlows.Add(1)
}

func (s *Server) serveTCP(r *tcp.ForwarderRequest, dst, src netip.AddrPort) {
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		s.refused.Add(1)
		r.Complete(true)
		s.logf("tunfe: accept %s -> %s: %v", src, dst, terr)
		return
	}
	r.Complete(false)
	client := gonet.NewTCPConn(&wq, ep)
	defer client.Close()

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	if dst.Port() == dnsPort {
		// TCP/53 is answered in process, exactly like UDP/53. An application
		// that got TC=1 and retried over TCP works here even though upstream
		// TCP/53 is reset at every port on the measured line, because the retry
		// never leaves the machine.
		s.dnsFlows.Add(1)
		s.serveDNSStream(ctx, client)
		return
	}

	name, _ := s.lookupName(dst.Addr())
	v := s.verdictFor(name, dst)
	ev := s.newEvent(name, dst, v)
	start := s.o.Now()
	err := s.flowTCP(ctx, client, name, dst, v, ev)
	s.finish(ev, start, err)
	if err != nil {
		s.logf("tunfe: %s: %v", targetLabel(name, dst), err)
	}
}

// flowTCP is the datapath, and the ORDER of its branches is the milestone's
// central correctness claim.
//
// A flow that is not judged is piped immediately, with no first-message read at
// all. The previous implementation read from the client unconditionally, with
// no deadline, before it consulted the port policy: SMTP, IMAP, POP3, FTP and
// MySQL all have the server greet first, so every one of them deadlocked until
// something timed out. Here nothing is read until the scope says this flow is
// one we judge, and even then the read is bounded and a silent client is the
// positive detection of a server-first protocol rather than a stall.
func (s *Server) flowTCP(ctx context.Context, client net.Conn, name string, dst netip.AddrPort,
	v policy.Verdict, ev *observ.ConnEvent) error {

	port := int(dst.Port())
	t := flow.Target{Name: name, Addr: dst, Port: port}

	if !judged(v) {
		return s.direct(ctx, client, t, nil, ev)
	}

	first, kind, meta, err := flow.ReadFirstMessage(client, port, s.o.FirstMsg)
	if err != nil {
		return fmt.Errorf("tunfe: read first message: %w", err)
	}
	if kind == flow.MsgServerFirst {
		// Nothing was buffered and nothing may be delayed. There is also
		// nothing to judge: the ladder decides on the client's first message,
		// and this client has not sent one.
		if ev != nil {
			ev.Strategy, ev.Attempts = "", 1
		}
		return s.direct(ctx, client, t, nil, ev)
	}

	// Naming: the DNS answer we ourselves served names the flow BEFORE any byte
	// is read, which is what the pipe-first decision above needs. Once the first
	// message is in hand the SNI supersedes it, because the reverse map is a
	// guess and the SNI is what this client actually asked for.
	//
	// Both halves matter. Without the SNI step a user who excluded their bank
	// would lose that exclusion the moment they ran with sudo — the regression
	// the previous tree shipped, where the exclusion list reached proxy mode's
	// options and TUN mode's had no such field. And without the SNI OVERRIDING a
	// reverse-map name, one CDN address serving two names (policy.ReverseMap
	// keeps the most recent) would judge a bank's connection under the other
	// name's verdict, which is the same defect wearing a different hat.
	if sni := meta.ServerName; sni != "" && !strings.EqualFold(sni, name) {
		name = sni
		t.Name = name
		v = s.o.Scope.ForName(name, port)
		if ev != nil {
			ev.Host = name
			ev.Scope, ev.Verdict, ev.Source = v.Class.String(), v.Class.String(), v.Source.String()
		}
		if !judged(v) {
			// The name says hands off. Send what we buffered, unmodified, and
			// relay: a bypassed host is never desynced and never escalated.
			return s.direct(ctx, client, t, first, ev)
		}
	}

	out, err := s.o.Ladder.Run(ctx, t, v, first, meta, nil)
	if ev != nil {
		fillOutcome(ev, out)
	}
	if out.Escalations() > 0 {
		s.escalated.Add(1)
	}
	if err != nil {
		return err
	}
	return s.relay(ctx, client, out.Conn, out.Pre, ev)
}

// direct dials and relays with nothing judged. pre is whatever was already read
// from the client and must be handed upstream before the relay starts.
func (s *Server) direct(ctx context.Context, client net.Conn, t flow.Target, pre []byte,
	ev *observ.ConnEvent) error {

	dctx, cancel := context.WithTimeout(ctx, s.o.DialTimeout)
	up, err := s.o.Dial.DialTCP(dctx, t)
	cancel()
	if err != nil {
		return err
	}
	if len(pre) > 0 {
		if _, werr := up.Write(pre); werr != nil {
			_ = up.Close()
			return fmt.Errorf("tunfe: write the buffered first message: %w", werr)
		}
	}
	return s.relay(ctx, client, up, nil, ev)
}

// relay writes the bytes the ladder already read and then joins the two
// connections.
//
// Writing Pre FIRST is not a detail: those are upstream bytes consumed while
// judging the attempt, and starting the relay without them leaves a hole in the
// client's stream that no later byte can fill.
func (s *Server) relay(ctx context.Context, client, up net.Conn, pre []byte, ev *observ.ConnEvent) error {
	counted := &countConn{Conn: up}
	defer func() {
		if ev != nil {
			ev.BytesUp, ev.BytesDown = counted.up.Load(), counted.down.Load()
		}
		_ = up.Close()
	}()

	if len(pre) > 0 {
		if _, err := client.Write(pre); err != nil {
			return fmt.Errorf("tunfe: write buffered upstream bytes: %w", err)
		}
		counted.down.Add(int64(len(pre)))
	}
	err := flow.Pipe(ctx, client, counted, flow.PipeOpts{
		Idle:      s.o.RelayIdle,
		HalfClose: true,
		Logf:      s.o.Logf,
	})
	if err != nil && !errors.Is(err, flow.ErrIdle) && ctx.Err() == nil {
		return err
	}
	return nil
}

// lookupName names a flow from the DNS answers we ourselves served.
func (s *Server) lookupName(ip netip.Addr) (string, bool) {
	if s.o.Reverse == nil || !ip.IsValid() {
		return "", false
	}
	return s.o.Reverse.Lookup(ip.Unmap())
}

// verdictFor asks the scope about a destination, by name when we have one and
// by address otherwise. An unnamed flow on an inspect port gets ScopeWatch and
// is judged by its own ClientHello, which under default-direct is exactly as
// safe as a named one — which is why this design needs no fake-IP layer.
func (s *Server) verdictFor(name string, dst netip.AddrPort) policy.Verdict {
	if name != "" {
		return s.o.Scope.ForName(name, int(dst.Port()))
	}
	return s.o.Scope.ForAddr(dst)
}

// judged reports whether a verdict means "buffer the first message and let the
// ladder decide". ScopeBypass and ScopeDirect are relayed with nothing
// buffered: the former because we have positive evidence the host breaks under
// desync, the latter because we already know it works plain.
func judged(v policy.Verdict) bool {
	return v.Class == policy.ScopeWatch || v.Class == policy.ScopeDesync
}

// newEvent starts a ConnEvent for one flow.
func (s *Server) newEvent(name string, dst netip.AddrPort, v policy.Verdict) *observ.ConnEvent {
	return &observ.ConnEvent{
		Time:    s.o.Now(),
		ID:      s.nextID.Add(1),
		Host:    name,
		Addr:    dst.String(),
		Port:    int(dst.Port()),
		Scope:   v.Class.String(),
		Verdict: v.Class.String(),
		Source:  v.Source.String(),
	}
}

// fillOutcome copies what the ladder decided onto the event.
func fillOutcome(ev *observ.ConnEvent, out flow.Outcome) {
	ev.Strategy = out.Spec
	ev.Attempts = len(out.Attempts)
	ev.Escalated = out.Escalations() > 0
	ev.Rung = out.Escalations()
}

// finish records the outcome and publishes the event.
func (s *Server) finish(ev *observ.ConnEvent, start time.Time, err error) {
	if ev == nil {
		return
	}
	ev.Duration = s.o.Now().Sub(start)
	switch {
	case err == nil:
		ev.Outcome = "ok"
	case errors.Is(err, flow.ErrNoUpstream):
		ev.Outcome = "refused"
	case errors.Is(err, flow.ErrLadderExhausted):
		ev.Outcome = "blocked"
	case errors.Is(err, flow.ErrNotReplayable):
		ev.Outcome = "not-replayable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		ev.Outcome = "cancelled"
	default:
		ev.Outcome = "error"
	}
	if err != nil {
		ev.Err = err.Error()
		s.failed.Add(1)
	}
	if s.o.OnConn != nil {
		s.o.OnConn(*ev)
	}
}

// countConn counts the bytes crossing an upstream connection so a ConnEvent can
// report them. Reads are "down" (origin to client) and writes are "up".
type countConn struct {
	net.Conn
	up, down atomic.Int64
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.down.Add(int64(n))
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.up.Add(int64(n))
	return n, err
}

// CloseWrite forwards a half-close. flow.Pipe discovers half-close support by
// type assertion, so without this an upstream *net.TCPConn's CloseWrite would
// be hidden by the wrapper and a client that shut down its write side and
// waited for the tail of a response would hang.
func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("tunfe: %T does not support half-close", c.Conn)
}

// addrPortOf converts a netstack address and port into a netip.AddrPort.
func addrPortOf(a tcpip.Address, port uint16) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), port), port != 0
}

// targetLabel renders a flow for a log line.
func targetLabel(name string, dst netip.AddrPort) string {
	if name == "" {
		return dst.String()
	}
	return fmt.Sprintf("%s[%s]", name, dst)
}
