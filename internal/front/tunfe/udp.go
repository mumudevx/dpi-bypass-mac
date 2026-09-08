package tunfe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// QUICPolicy decides what happens to a QUIC Initial addressed to a name we
// judge. A bypassed or unjudged flow is always relayed, whatever this says.
type QUICPolicy uint8

const (
	// QUICRefuse answers the Initial with an ICMP port-unreachable, which is
	// how a browser is told to fall back to TCP within the same RTT — and TCP
	// is where the whole measured ladder applies. It is the zero value because
	// it is the shipped default (docs/PLAN.md data path E).
	QUICRefuse QUICPolicy = iota
	// QUICRelay forwards the datagram verbatim. It is what a UDP flow to a
	// bypassed name gets, and what an operator selects when measurement says
	// QUIC is not blocked on this line.
	QUICRelay
	// QUICDesync emits the Initial through Options.QUICStrategy — in this build
	// that is quicfake, N low-hop-limit decoy Initials carrying the real DCID
	// ahead of the real datagram, which DOSSIER §3 (P2) records as byedpi's
	// desync_udp and which is ungated on Darwin.
	//
	// It is NOT a default and must not become one on this evidence: its
	// efficacy against Turkish DPI is unmeasured, while refusing the Initial
	// buys the TCP fallback, where every strategy in MEASUREMENTS.md §3 was
	// actually measured. It is here so `dpb probe` can measure it on a user's
	// own line, and so an operator whose measurements say it works can select
	// it.
	//
	// Failure is refusal, never a plain relay: if the plan cannot be built or
	// emitted, the client gets the ICMP unreachable and falls back to TCP,
	// rather than sending an unprotected Initial to a name we judge.
	QUICDesync
)

var quicPolicyNames = [...]string{"refuse", "relay", "desync"}

func (p QUICPolicy) String() string {
	if int(p) < len(quicPolicyNames) {
		return quicPolicyNames[p]
	}
	return fmt.Sprintf("quicpolicy(%d)", uint8(p))
}

const (
	// dnsPort is answered in process and never relayed.
	dnsPort = 53
	// quicPort is the UDP port the QUIC policy applies to.
	quicPort = 443
	// maxDatagram bounds one relayed datagram. Larger than anything a
	// 1500-byte-MTU link delivers, with room for a reassembled jumbo DNS
	// reply.
	maxDatagram = 64 << 10
)

// handleUDP accepts one forwarded UDP session.
//
// Unlike the TCP forwarder, gVisor calls this INLINE on the dispatcher
// goroutine — which is our own device read loop — so it must not block. The
// endpoint is created here because the request holds the first datagram and
// creating it is what delivers that datagram; everything after is handed to a
// flow.Safe goroutine.
func (s *Server) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst, dok := addrPortOf(id.LocalAddress, id.LocalPort)
	src, sok := addrPortOf(id.RemoteAddress, id.RemotePort)
	if !dok || !sok {
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		s.logf("tunfe: udp %s -> %s: %v", src, dst, terr)
		return
	}
	client := gonet.NewUDPConn(&wq, ep)

	// The endpoint already exists by the time track is asked, so a refusal here
	// has to close it: the netstack handed us a live UDP endpoint and nothing
	// else is going to give it back.
	if dst.Port() == dnsPort {
		if !s.track("tunfe/udp-dns", func() {
			defer client.Close()
			defer s.closeOnCancel("tunfe/udp-dns-cancel", client)()
			s.serveDNSDatagrams(client, dst)
		}) {
			_ = client.Close()
			s.refused.Add(1)
			return
		}
		s.dnsFlows.Add(1)
		return
	}
	if !s.track("tunfe/udp", func() {
		defer client.Close()
		defer s.closeOnCancel("tunfe/udp-cancel", client)()
		s.serveUDP(client, src, dst)
	}) {
		_ = client.Close()
		s.refused.Add(1)
		return
	}
	s.udpFlows.Add(1)
}

// closeOnCancel closes c when the datapath's context ends, and returns the
// function that stops the watcher.
//
// A UDP session has no FIN, so the idle deadline is the ONLY bound on either
// copy loop — DefaultUDPIdle, sixty seconds, in the shipped configuration.
// Without this, cancelling the datapath does not touch a live relay at all:
// Serve returns, drain() waits out DrainGrace and logs "flow(s) still live",
// and a session goes on holding a client endpoint on a netstack that is being
// torn down and an upstream socket on a route that is being withdrawn, for up
// to a minute after the user ran `dpb off`.
//
// Closing the CLIENT conn is enough to unwind the whole session: the upstream
// copy's read fails, its deferred closeBoth closes the upstream socket, and the
// downstream copy ends on that. It also covers the first read in serveUDP and
// the whole of serveDNSDatagrams, which are parked on the same conn.
//
// The returned function stops the watcher AND waits for it, so the watcher can
// never outlive the conn it watches.
func (s *Server) closeOnCancel(name string, c io.Closer) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	flow.Safe(name, s.o.Logf, func() {
		defer close(done)
		select {
		case <-s.ctx.Done():
			_ = c.Close()
		case <-stop:
		}
	})
	return func() {
		close(stop)
		<-done
	}
}

// serveUDP applies policy to one datagram session and then relays it.
func (s *Server) serveUDP(client net.Conn, src, dst netip.AddrPort) {
	idle := s.o.UDPIdle
	buf := make([]byte, maxDatagram)
	if err := client.SetReadDeadline(s.o.Now().Add(idle)); err != nil {
		return
	}
	n, err := client.Read(buf)
	if n <= 0 {
		if err != nil && !isTimeoutErr(err) {
			s.logf("tunfe: udp %s -> %s: %v", src, dst, err)
		}
		return
	}
	first := buf[:n]

	name, _ := s.lookupName(dst.Addr())
	v := s.verdictFor(name, dst)
	action := s.quicAction(v, dst, first)
	if action == quicRefuse {
		s.refuseFlow(src, dst, n, name, "policy refuses QUIC to a name we judge")
		return
	}

	if s.o.UDPDial == nil {
		s.logf("tunfe: cannot relay %s -> %s: %v", src, dst, ErrNoUDPDialer)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.o.DialTimeout)
	up, derr := s.o.UDPDial.DialUDP(ctx, dst)
	cancel()
	if derr != nil {
		s.logf("tunfe: udp dial %s: %v", dst, derr)
		return
	}
	defer up.Close()

	if err := up.SetWriteDeadline(s.o.Now().Add(idle)); err != nil {
		return
	}
	if err := s.sendFirstDatagram(up, first, dst, action); err != nil {
		s.logf("tunfe: udp write %s: %v", dst, err)
		if action == quicDesync {
			// Fail CLOSED. The alternative — relaying the Initial plain because
			// the desync did not work — sends an unprotected ClientHello for a
			// name we judge, which is the one outcome this policy exists to
			// prevent. The unreachable puts the client on TCP instead.
			s.refuseFlow(src, dst, n, name, "the UDP strategy could not be emitted")
		}
		return
	}
	s.relayDatagrams(client, up, idle)
}

// quicAction is what happens to this datagram.
type quicAction uint8

const (
	quicPass   quicAction = iota // relay it verbatim
	quicRefuse                   // ICMP port-unreachable, no datagram upstream
	quicDesync                   // emit it through Options.QUICStrategy
)

// quicAction decides whether this datagram is a QUIC Initial to a name we
// judge, and if so what the policy does with it.
//
// Both halves of the test matter. A bypassed or already-direct flow is never
// touched: those are the hosts we have evidence about, and breaking their QUIC
// would be a regression bought for nothing. And only an Initial is acted on — a
// datagram in the middle of an established session belongs to a flow the client
// already has, and refusing that would tear down a working connection.
func (s *Server) quicAction(v policy.Verdict, dst netip.AddrPort, datagram []byte) quicAction {
	if s.o.QUIC == QUICRelay || dst.Port() != quicPort || !judged(v) {
		return quicPass
	}
	if _, ok := tlsmsg.ParseQUICInitial(datagram); !ok {
		return quicPass
	}
	if s.o.QUIC == QUICDesync {
		return quicDesync
	}
	return quicRefuse
}

// sendFirstDatagram puts the flow's first datagram on the upstream socket,
// applying the UDP strategy when policy asked for one.
func (s *Server) sendFirstDatagram(up net.Conn, first []byte, dst netip.AddrPort, action quicAction) error {
	if action != quicDesync {
		n, err := up.Write(first)
		if err != nil {
			return err
		}
		if n != len(first) {
			return fmt.Errorf("tunfe: wrote %d of %d bytes to %s", n, len(first), dst)
		}
		return nil
	}
	return flow.SendFirstDatagram(s.ctx, up, first, s.o.QUICStrategy, s.o.Sender, int(dst.Port()))
}

// refuseFlow answers a datagram with an ICMP port-unreachable and says why.
//
// Refusing rather than dropping is the whole point: Chrome and Firefox mark a
// path QUIC-broken on the first unreachable and retry over TCP within the same
// RTT, where the measured ladder applies. A drop costs the user a QUIC connect
// timeout first.
func (s *Server) refuseFlow(src, dst netip.AddrPort, payloadLen int, name, why string) {
	if rerr := s.refuse(src, dst, payloadLen); rerr != nil {
		s.logf("tunfe: refuse quic to %s: %v", targetLabel(name, dst), rerr)
		return
	}
	s.logf("tunfe: refused a QUIC Initial to %s with ICMP port-unreachable (%s); "+
		"the client falls back to TCP, where the measured ladder applies", targetLabel(name, dst), why)
}

// relayDatagrams pumps both directions until one of them ends or the session
// goes idle.
func (s *Server) relayDatagrams(client, up net.Conn, idle time.Duration) {
	var once sync.Once
	closeBoth := func() { _ = client.Close(); _ = up.Close() }
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		defer func() {
			once.Do(closeBoth)
			done <- struct{}{}
		}()
		s.copyDatagrams(dst, src, idle)
	}
	flow.Safe("tunfe/udp-up", s.o.Logf, func() { copyOne(up, client) })
	flow.Safe("tunfe/udp-down", s.o.Logf, func() { copyOne(client, up) })
	<-done
	<-done
}

// copyDatagrams relays src to dst one datagram at a time.
//
// io.Copy is wrong here and the comment is load-bearing: a stream copy
// re-frames, so a short read truncates a datagram and a buffered write merges
// two of them. UDP has no stream to re-frame, and a QUIC or DNS peer that
// receives two datagrams glued together simply discards them.
func (s *Server) copyDatagrams(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, maxDatagram)
	for {
		if err := src.SetReadDeadline(s.o.Now().Add(idle)); err != nil {
			return
		}
		n, err := src.Read(buf)
		if n > 0 {
			if werr := dst.SetWriteDeadline(s.o.Now().Add(idle)); werr != nil {
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			// An idle session is reaped rather than reported: UDP has no FIN,
			// so the deadline IS the end of the session.
			return
		}
	}
}

// isTimeoutErr recognises a deadline however it was spelled: gonet reports one
// as a *net.OpError wrapping its own timeout type, and a kernel socket reports
// os.ErrDeadlineExceeded.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
