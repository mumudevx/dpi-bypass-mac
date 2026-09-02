// Package proxyfe is the unprivileged front end: an HTTP CONNECT, plaintext
// HTTP and SOCKS5 proxy on loopback, plus the PAC that points macOS at it.
//
// It is the SECOND consumer of internal/flow, after the prober, and it uses the
// same engine with no special cases. That is the whole point of the
// default-direct design: one code path decides whether a host needs a desync,
// learns the answer and caches it, so `dpb probe`, the proxy and (later) the
// tunnel cannot disagree about a host.
//
// The datapath is the four steps of internal/flow/e2e_test.go's serve helper:
// read the complete first message, walk the ladder, write the bytes the ladder
// already read from upstream, then relay.
package proxyfe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// Defaults for the bounds a caller did not set. Every one is a bound, not a
// target.
const (
	// DefaultClientIdle is how long a client connection may sit without sending
	// a request. Browsers open speculative connections and hold them, so this
	// is generous; it exists so a forgotten connection is eventually reaped.
	DefaultClientIdle = 60 * time.Second
	// DefaultRelayIdle closes a relay whose two directions have both been quiet
	// this long.
	DefaultRelayIdle = 120 * time.Second
	// DefaultDrainGrace bounds how long Serve waits for live connections after
	// its context is cancelled. Teardown has a 10 s budget in total and the
	// system settings still have to be reverted inside it, so the relays get a
	// fraction of that and are then abandoned to the process exit.
	DefaultDrainGrace = 3 * time.Second
)

// ErrNoLadder is returned by New when the engine is missing. It is a
// programming error rather than a runtime condition, and failing at
// construction is the only way it never becomes a connection that silently
// relays everything unjudged.
var ErrNoLadder = errors.New("proxyfe: no ladder runner")

// ErrNoScope is returned by New when no policy scope was supplied.
var ErrNoScope = errors.New("proxyfe: no policy scope")

// Options configures a Server. Everything is injected: the scope, the engine,
// the dialer, the clock. The package has no global state and opens no socket it
// was not handed.
type Options struct {
	// Scope decides what happens to a flow before any byte is read.
	Scope policy.Scope
	// Ladder is the shared engine. It owns dialling for a judged flow.
	Ladder *flow.LadderRunner
	// Dial opens the upstream for a flow that is NOT judged — ScopeDirect and
	// ScopeBypass, which are relayed with nothing buffered. It is the same
	// dialer the ladder holds; passing it here keeps the direct path from
	// reaching into the ladder for it.
	Dial flow.Dialer
	// Resolve is the tool's own chain, used only as a pre-flight before a
	// CONNECT is acknowledged: see connect.go's comment on ordering.
	Resolve flow.ResolveFunc
	// PAC, when non-nil, is served at PACPath.
	PAC *PAC
	// UDPDial opens the upstream socket for a SOCKS5 UDP ASSOCIATE flow. Nil
	// means ASSOCIATE is answered with the RFC's "command not supported"
	// instead of a socket nothing is behind.
	UDPDial flow.UDPDialer
	// DNS answers UDP/53 for an association in process. Relaying it would hand
	// the ISP's resolver exactly the queries DoH exists to hide.
	DNS DNSAnswerer
	// QUIC selects what happens to a UDP/443 QUIC Initial addressed to a name
	// we judge. The zero value is QUICRefuse, the shipped default.
	QUIC QUICPolicy
	// QUICStrategy is the plan QUICDesync emits an Initial through; required by
	// that policy and ignored by the others.
	QUICStrategy strategy.Strategy
	// Sender executes a UDP plan. Nil is the shared default sender.
	Sender *emit.Sender
	// UDPIdle reaps a datagram session with no traffic in either direction, and
	// MaxUDPSessions bounds the upstream sockets one association may hold.
	// Zero means the defaults.
	UDPIdle        time.Duration
	MaxUDPSessions int
	// FirstMsg bounds the first-message read. The zero value is
	// flow.DefaultFirstMsgOpts().
	FirstMsg flow.FirstMsgOpts
	// ClientIdle and RelayIdle bound an idle client connection and an idle
	// relay. Zero means the defaults above.
	ClientIdle time.Duration
	RelayIdle  time.Duration
	// DrainGrace bounds the wait for live connections at shutdown.
	DrainGrace time.Duration
	// MaxConns caps concurrent client connections. Zero means unlimited.
	MaxConns int
	// OnConn receives one event per finished client flow. May be nil.
	OnConn func(observ.ConnEvent)
	Now    func() time.Time
	Logf   func(string, ...any)
}

// Stats is what `dpb status` reads off a running server.
type Stats struct {
	Accepted  uint64
	Active    int64
	CONNECT   uint64
	HTTP      uint64
	SOCKS     uint64
	UDPAssoc  uint64
	UDPDrops  uint64
	PAC       uint64
	Rejected  uint64
	Failed    uint64
	Escalated uint64
}

// Server accepts client connections and dispatches them by protocol.
type Server struct {
	o Options

	wg sync.WaitGroup

	accepted   atomic.Uint64
	active     atomic.Int64
	connect    atomic.Uint64
	httpReqs   atomic.Uint64
	socks      atomic.Uint64
	udpAssoc   atomic.Uint64
	udpRefused atomic.Uint64
	pacHits    atomic.Uint64
	rejected   atomic.Uint64
	failed     atomic.Uint64
	escalated  atomic.Uint64
	nextID     atomic.Uint64
}

// New validates the wiring and returns a Server.
func New(o Options) (*Server, error) {
	if o.Ladder == nil {
		return nil, ErrNoLadder
	}
	if o.Scope == nil {
		return nil, ErrNoScope
	}
	if o.Dial == nil {
		// The direct path needs a dialer of its own, and reaching into the
		// ladder's would tie the two together. Refusing beats silently sending
		// every ScopeDirect flow through the judging path.
		o.Dial = o.Ladder.Dial
	}
	if o.Dial == nil {
		return nil, fmt.Errorf("proxyfe: no dialer")
	}
	if o.FirstMsg == (flow.FirstMsgOpts{}) {
		o.FirstMsg = flow.DefaultFirstMsgOpts()
	}
	if o.ClientIdle <= 0 {
		o.ClientIdle = DefaultClientIdle
	}
	if o.RelayIdle <= 0 {
		o.RelayIdle = DefaultRelayIdle
	}
	if o.DrainGrace <= 0 {
		o.DrainGrace = DefaultDrainGrace
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Server{o: o}, nil
}

// Stats reports the counters.
func (s *Server) Stats() Stats {
	return Stats{
		Accepted:  s.accepted.Load(),
		Active:    s.active.Load(),
		CONNECT:   s.connect.Load(),
		HTTP:      s.httpReqs.Load(),
		SOCKS:     s.socks.Load(),
		UDPAssoc:  s.udpAssoc.Load(),
		UDPDrops:  s.udpRefused.Load(),
		PAC:       s.pacHits.Load(),
		Rejected:  s.rejected.Load(),
		Failed:    s.failed.Load(),
		Escalated: s.escalated.Load(),
	}
}

func (s *Server) logf(format string, a ...any) {
	if s.o.Logf != nil {
		s.o.Logf(format, a...)
	}
}

// Serve accepts on ln until ctx is cancelled or the listener fails.
//
// Cancelling ctx closes ln — a blocking Accept has no other way to be
// interrupted — so the listener may not be reused afterwards. Serve then waits
// up to DrainGrace for live connections and returns nil: a cancelled context is
// a normal shutdown, not an error.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	closed := make(chan struct{})
	flow.Safe("proxyfe/listener-closer", s.o.Logf, func() {
		defer close(closed)
		<-ctx.Done()
		_ = ln.Close()
	})

	var retErr error
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				retErr = fmt.Errorf("proxyfe: accept on %s: %w", ln.Addr(), err)
			}
			break
		}
		s.accepted.Add(1)
		if s.o.MaxConns > 0 && int(s.active.Load()) >= s.o.MaxConns {
			// Refusing is the honest answer. Accepting and queueing would make
			// the browser wait on a connection nothing is going to serve.
			s.rejected.Add(1)
			s.logf("proxyfe: refusing %s: %d connections already active", c.RemoteAddr(), s.o.MaxConns)
			_ = c.Close()
			continue
		}
		s.active.Add(1)
		s.wg.Add(1)
		conn := c
		flow.Safe("proxyfe/conn", s.o.Logf, func() {
			defer s.wg.Done()
			defer s.active.Add(-1)
			defer conn.Close()
			s.handle(ctx, conn)
		})
	}

	cancel()
	<-closed
	s.drain()
	return retErr
}

// drain waits for live connections, but only for DrainGrace. A relay wedged on
// a socket that will never return must not hold up the revert of the system
// proxy settings: the process is about to exit and take the socket with it,
// whereas an unreverted proxy setting outlives us.
func (s *Server) drain() {
	done := make(chan struct{})
	flow.Safe("proxyfe/drain", s.o.Logf, func() {
		defer close(done)
		s.wg.Wait()
	})
	t := time.NewTimer(s.o.DrainGrace)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		s.logf("proxyfe: %d connection(s) still live after %s; leaving them to process exit",
			s.active.Load(), s.o.DrainGrace)
	}
}

// handle dispatches one client connection by looking at its first byte.
//
// 0x05 is a SOCKS5 version byte and can never begin an HTTP request line, whose
// first byte is always an uppercase method letter. One byte of lookahead is
// therefore a complete discrimination, and it is peeked rather than read so the
// chosen handler sees the stream whole.
func (s *Server) handle(ctx context.Context, c net.Conn) {
	br := bufio.NewReader(c)
	if err := c.SetReadDeadline(s.o.Now().Add(s.o.ClientIdle)); err != nil {
		s.logf("proxyfe: %s: set deadline: %v", c.RemoteAddr(), err)
		return
	}
	first, err := br.Peek(1)
	if err != nil {
		// A client that connected and said nothing is ordinary: browsers
		// pre-open connections they never use.
		return
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		s.logf("proxyfe: %s: clear deadline: %v", c.RemoteAddr(), err)
		return
	}

	client := &bufConn{Conn: c, r: br}
	if first[0] == socks5Version {
		s.socks.Add(1)
		s.serveSOCKS(ctx, client)
		return
	}
	s.serveHTTP(ctx, client)
}

// bufConn is a net.Conn whose reads come from a bufio.Reader that has already
// consumed part of the stream.
//
// It exists because every handler here peeks before it decides, and the bytes
// the peek buffered belong to whatever comes next — flow.ReadFirstMessage,
// flow.Pipe, or the next HTTP request on the same connection. Reading the conn
// directly after a peek loses them.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite forwards a half-close. flow.Pipe discovers half-close support by
// type assertion, so without this the wrapper would hide a *net.TCPConn's
// CloseWrite and a client waiting for the tail of a response after shutting
// down its own write side would hang.
func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("proxyfe: %T does not support half-close", c.Conn)
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

func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("proxyfe: %T does not support half-close", c.Conn)
}

// splitHostPort parses an authority, supplying def when no port is written.
func splitHostPort(authority string, def int) (host string, port int, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0, fmt.Errorf("proxyfe: empty destination")
	}
	h, p, serr := net.SplitHostPort(authority)
	if serr != nil {
		// No port, or a bare IPv6 literal. netip tells the two apart without
		// guessing at the colon count.
		if a, aerr := netip.ParseAddr(strings.Trim(authority, "[]")); aerr == nil {
			return a.String(), def, nil
		}
		if strings.Contains(authority, ":") {
			return "", 0, fmt.Errorf("proxyfe: %q is not host:port", authority)
		}
		return strings.ToLower(authority), def, nil
	}
	n, cerr := strconv.Atoi(p)
	if cerr != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("proxyfe: %q has no usable port", authority)
	}
	if a, aerr := netip.ParseAddr(h); aerr == nil {
		return a.String(), n, nil
	}
	if h == "" {
		return "", 0, fmt.Errorf("proxyfe: %q has no host", authority)
	}
	return strings.ToLower(h), n, nil
}

// target builds the flow.Target for a destination. A literal address is pinned
// so no resolution happens at all; a name is left for the dialer to resolve
// through the tool's own chain.
func target(host string, port int) flow.Target {
	t := flow.Target{Name: host, Port: port}
	if a, err := netip.ParseAddr(host); err == nil {
		t.Addr = netip.AddrPortFrom(a, uint16(port))
		t.Name = ""
	}
	return t
}

// isLiteral reports whether host is an address rather than a name.
func isLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// verdictFor asks the scope about a destination. An IP-literal destination is
// asked about by address, because there is no name to key a rule on.
func (s *Server) verdictFor(host string, port int) policy.Verdict {
	if a, err := netip.ParseAddr(host); err == nil {
		return s.o.Scope.ForAddr(netip.AddrPortFrom(a, uint16(port)))
	}
	return s.o.Scope.ForName(host, port)
}

// judged reports whether a verdict means "buffer the first message and let the
// ladder decide". ScopeBypass and ScopeDirect are relayed with nothing
// buffered: the former because we have positive evidence the host breaks under
// desync, the latter because we already know it works plain.
func judged(v policy.Verdict) bool {
	return v.Class == policy.ScopeWatch || v.Class == policy.ScopeDesync
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
			return fmt.Errorf("proxyfe: write buffered upstream bytes: %w", err)
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

// newEvent starts a ConnEvent for one client flow.
func (s *Server) newEvent(host string, port int, v policy.Verdict) *observ.ConnEvent {
	return &observ.ConnEvent{
		Time:    s.o.Now(),
		ID:      s.nextID.Add(1),
		Host:    host,
		Port:    port,
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
	for _, a := range out.Attempts {
		if a.Addr.IsValid() {
			ev.Addr = a.Addr.String()
		}
	}
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

// isRefused reports whether the failure was a peer that answered with a reset.
// It is used only to pick a SOCKS5 reply code; the datapath itself classifies
// failures through flow.Classify, which knows the difference between a refusal
// and censorship.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// isUnreachable reports whether the failure was the network rather than the
// peer.
func isUnreachable(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, flow.ErrNoResolver)
}
