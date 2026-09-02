package tunfe

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Shutdown and the flow counter.
//
// `go test ./internal/front/tunfe/ -race -count=10` reported this as a genuine
// DATA RACE, not a flake:
//
//	WARNING: DATA RACE
//	Write at 0x00c00012c4d8 by goroutine 2448:
//	  internal/flow.Safe.func1()          safe.go:80
//	  ... created at (*Server).drain()    stack.go:379   // s.wg.Wait()
//	Previous read at 0x00c00012c4d8 by goroutine 2430:
//	  (*Server).handleUDP()               udp.go:99      // s.wg.Add(1)
//	  ... udp.(*Forwarder).HandlePacket() ... (*endpoint).readLoop()
//	--- FAIL: TestDNSWithNoResolverIsDroppedNotRelayed (0.33s)
//
// The read loop keeps delivering packets to the forwarders while Serve's defer
// is already draining, so an Add lands concurrently with a Wait. sync's
// contract does not define that, and both outcomes it permits are bad: a flow
// the drain never waits for, or a "WaitGroup misuse" panic on the device read
// loop — which is the one goroutine whose death strands the capture routes.

// TestTrackAndDrainDoNotRaceOnTheFlowCounter is that race, reduced to the two
// goroutines that produce it so it reproduces in milliseconds rather than in
// the ten -race rounds it took to surface through the netstack.
//
// It asserts nothing by hand: the race detector is the assertion, which is why
// this test is worth nothing without -race and is left cheap enough to run
// under it every time.
func TestTrackAndDrainDoNotRaceOnTheFlowCounter(t *testing.T) {
	t.Parallel()
	for round := 0; round < 200; round++ {
		// A LONG grace on purpose. drain() gives up after DrainGrace whether or
		// not the flows finished, so a short one here would make the assertion
		// below a race against the scheduler rather than a statement about the
		// code — the shape of flake this package has already been bitten by
		// twice. Nothing waits it out: with no-op flows the wait completes at
		// once, and active is decremented before wg.Done, so a drain that
		// returns has seen every decrement.
		s := &Server{o: Options{DrainGrace: 30 * time.Second, Logf: t.Logf}}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.drain()
		}()
		go func() {
			defer wg.Done()
			// The forwarders' side: flows keep arriving while the drain runs.
			for i := 0; i < 32; i++ {
				s.track("tunfe/test", func() {})
			}
		}()
		wg.Wait()

		if n := s.active.Load(); n != 0 {
			t.Fatalf("round %d: %d flow(s) still counted as active after drain and every "+
				"tracked flow returned", round, n)
		}
	}
}

// TestTrackRefusesAFlowOnceDrainHasClosedTheCounter pins the contract the fix
// rests on. drain() waits on the counter, so nothing may be added to it
// afterwards — and the caller has to learn that, because it is holding a client
// endpoint or a half-open forwarder request that nothing else will release.
func TestTrackRefusesAFlowOnceDrainHasClosedTheCounter(t *testing.T) {
	t.Parallel()
	// Long, for the reason spelled out above: a drain that gives up early would
	// make the active-count assertion a race against the scheduler.
	s := &Server{o: Options{DrainGrace: 30 * time.Second, Logf: t.Logf}}

	if !s.track("tunfe/test", func() {}) {
		t.Fatal("track refused a flow on a datapath that has not drained")
	}
	s.drain()

	ran := make(chan struct{})
	if s.track("tunfe/test", func() { close(ran) }) {
		t.Fatal("track admitted a flow after drain returned; that Add raced the Wait drain " +
			"had already made, and the flow would hold a client endpoint on a netstack " +
			"that is being torn down")
	}
	select {
	case <-ran:
		t.Fatal("a refused flow ran anyway")
	default:
	}
	if n := s.active.Load(); n != 0 {
		t.Fatalf("a refused flow was counted as active (%d)", n)
	}
}

// TestAFlowArrivingAfterTheDrainIsResetNotStarted is the same contract seen
// from the wire, through the real netstack and the real forwarder.
//
// The client must not be left hanging: an unanswered SYN costs it a full
// connect timeout, so a flow that arrives too late is reset and counted as
// refused rather than dropped.
func TestAFlowArrivingAfterTheDrainIsResetNotStarted(t *testing.T) {
	o := newOrigin(t)
	// noStart: the datapath is live (CreateNIC attached the endpoint and its
	// read loop) but no supervisor owns it, so the test can run the drain that
	// Serve's defer would run and then deliver a packet behind it.
	l := newLab(t, labOpts{noStart: true, firstMsg: shortFirstMsg()})
	l.up.serveOn(o.addr())

	l.server.drain()

	if c, err := l.dial(netip.AddrPortFrom(originIP, 25)); err == nil {
		_ = c.Close()
		t.Fatal("a TCP flow was accepted after the datapath drained")
	}
	st := l.server.Stats()
	if st.Refused == 0 {
		t.Fatal("the late flow was dropped rather than reset and counted")
	}
	if st.TCPFlows != 0 {
		t.Fatalf("TCPFlows = %d, want 0: a flow that was never started must not be counted",
			st.TCPFlows)
	}
	if st.Active != 0 {
		t.Fatalf("Active = %d after a refused flow, want 0", st.Active)
	}
	if n := len(l.up.targets()); n != 0 {
		t.Fatalf("%d upstream dial(s) for a flow the datapath had already stopped serving", n)
	}
}
