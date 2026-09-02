package tunfe

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// The UDP idle reaper, tested on a fake clock.
//
// UDP has no FIN, so Options.UDPIdle is the ONLY bound on a datagram session:
// without the reaper every flow leaks a client endpoint, an upstream socket and
// two goroutines for the life of the process. It is read in exactly two places
// — serveUDP/copyDatagrams in udp.go and serveDNSDatagrams in dns.go — and when
// the lab's UDPIdle was raised from 1 s to 20 s to stop a flake, nothing was
// left asserting that either one reaps anything at all.
//
// These tests restore that coverage without waiting out a real idle period.
// The reaper computes its deadline from Options.Now and the CONNECTION enforces
// it against real time, so the clock is what places the deadline relative to
// now: a clock reading real time arms a deadline a full idle period in the
// future (the session is inside its window), and a clock one idle period behind
// arms a deadline that has already passed (the session has been idle for its
// whole budget). Neither costs a second of wall time.

// idleBudget is deliberately much longer than any wait in this file, so a test
// that passes by waiting the session out rather than by reaping it would blow
// its own bound instead of quietly succeeding.
const idleBudget = 30 * time.Second

// fakeClock is Options.Now under test control.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// atRealTime places the clock at the wall clock: a deadline armed from it lies
// one full idle period in the future.
func (c *fakeClock) atRealTime() { c.set(time.Now()) }

// oneIdlePeriodBehind places the clock so that a deadline armed from it has
// already passed — the session has been idle for its entire budget.
func (c *fakeClock) oneIdlePeriodBehind() { c.set(time.Now().Add(-idleBudget)) }

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// pipePair is two net.Pipe halves with their cleanup registered. net.Pipe
// honours deadlines, which is the whole reason it stands in for the netstack
// endpoint here.
func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// TestUDPRelayIsReapedWhenTheSessionGoesIdle covers udp.go's copy loop, which
// is where a relayed datagram session actually ends.
func TestUDPRelayIsReapedWhenTheSessionGoesIdle(t *testing.T) {
	t.Parallel()

	t.Run("inside the idle window it keeps the session", func(t *testing.T) {
		t.Parallel()
		clk := &fakeClock{}
		clk.atRealTime()
		s := &Server{o: Options{Now: clk.now, Logf: t.Logf}}

		src, srcPeer := pipePair(t)
		dst, _ := pipePair(t)

		done := make(chan struct{})
		go func() {
			defer close(done)
			s.copyDatagrams(dst, src, idleBudget)
		}()

		select {
		case <-done:
			t.Fatal("the copy loop gave up on a session that is inside its idle window; " +
				"UDPIdle would then be a session lifetime rather than an idle bound")
		case <-time.After(100 * time.Millisecond):
		}

		// End it the way a closed endpoint would, so the goroutine does not
		// outlive the test.
		_ = srcPeer.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the copy loop outlived its source connection")
		}
	})

	t.Run("past the idle deadline it reaps the session", func(t *testing.T) {
		t.Parallel()
		clk := &fakeClock{}
		clk.oneIdlePeriodBehind()
		s := &Server{o: Options{Now: clk.now, Logf: t.Logf}}

		src, _ := pipePair(t)
		dst, _ := pipePair(t)

		done := make(chan struct{})
		start := time.Now()
		go func() {
			defer close(done)
			s.copyDatagrams(dst, src, idleBudget)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("a UDP session idle for its whole %s budget was not reaped; UDP has no "+
				"FIN, so nothing else would ever end it and it would hold a client endpoint "+
				"and an upstream socket until the process exits", idleBudget)
		}
		if el := time.Since(start); el > idleBudget {
			t.Fatalf("the session took %s to reap, which is past its own %s budget", el, idleBudget)
		}
	})
}

// TestUDPFirstReadIsBoundedByUDPIdle covers the OTHER read in udp.go: the one
// before any upstream exists. A client that opens a UDP session and then says
// nothing must not pin a goroutine, and must not cost an upstream dial.
func TestUDPFirstReadIsBoundedByUDPIdle(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{}
	clk.oneIdlePeriodBehind()
	dialer := &countingUDPDialer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{
		o: Options{UDPIdle: idleBudget, UDPDial: dialer, Now: clk.now, Logf: t.Logf},
		// serveUDP derives the dial context from the datapath's, so it has to
		// exist even on the path that never dials.
		ctx:    ctx,
		cancel: cancel,
	}

	client, _ := pipePair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveUDP(client, netip.AddrPortFrom(clientIP, 51000), netip.AddrPortFrom(originIP, 443))
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("a UDP session that sent nothing was not reaped after its %s idle budget", idleBudget)
	}
	if n := dialer.count(); n != 0 {
		t.Fatalf("%d upstream dial(s) for a session that never sent a datagram", n)
	}
}

// TestDNSSessionIsReapedWhenItGoesIdle covers dns.go's own use of UDPIdle.
//
// The in-process DNS session is a loop over one client conn, so a stub that
// opens a session and goes away leaves that loop parked. It is reaped on the
// same idle bound, and it must not have asked the chain anything on the way
// out.
func TestDNSSessionIsReapedWhenItGoesIdle(t *testing.T) {
	t.Parallel()
	srv, scripted := newTestResolver(t, policy.NewReverseMap(4),
		map[string]netip.Addr{"discord.com.": originIP})
	clk := &fakeClock{}
	clk.oneIdlePeriodBehind()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{
		o:      Options{DNS: srv, UDPIdle: idleBudget, Now: clk.now, Logf: t.Logf},
		ctx:    ctx,
		cancel: cancel,
	}

	client, _ := pipePair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveDNSDatagrams(client, netip.AddrPortFrom(resolverIP, 53))
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("an idle in-process DNS session was not reaped after its %s budget", idleBudget)
	}
	if n := scripted.asked.Load(); n != 0 {
		t.Fatalf("the chain was asked %d question(s) by a session that sent no query", n)
	}
}
