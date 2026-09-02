package netwatch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testnet"
)

// fakeClock puts the two axes under the test's control. testnet.Clock drives
// the monotonic axis and every timer; skew is how far the wall clock has run
// ahead of it, which is exactly what a sleep does on darwin.
type fakeClock struct {
	c *testnet.Clock

	mu   sync.Mutex
	skew time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{c: testnet.NewClock(epoch)} }

func (f *fakeClock) Now() Instant {
	m := f.c.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	return Instant{Mono: m, Wall: m.Add(f.skew)}
}

func (f *fakeClock) After(d time.Duration) <-chan time.Time { return f.c.After(d) }

// sleep simulates a closed lid: wall time passes, the monotonic clock does not.
func (f *fakeClock) sleep(d time.Duration) {
	f.mu.Lock()
	f.skew += d
	f.mu.Unlock()
}

// chanSource is a Source a test drives by hand.
type chanSource struct {
	ch   chan struct{}
	runs chan struct{} // one value per Run call, for the retry test
	err  error
	once sync.Once
}

func newChanSource() *chanSource {
	return &chanSource{ch: make(chan struct{}, 8), runs: make(chan struct{}, 8)}
}

func (s *chanSource) Run(ctx context.Context, out chan<- struct{}) error {
	select {
	case s.runs <- struct{}{}:
	default:
	}
	if s.err != nil {
		var first bool
		s.once.Do(func() { first = true })
		if first {
			return s.err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.ch:
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}
}

func (s *chanSource) signal() { s.ch <- struct{}{} }

// harness wires a Watcher to a fake clock, a fake source and a step recorder.
type harness struct {
	t      *testing.T
	clock  *fakeClock
	src    *chanSource
	steps  chan string
	events chan Event

	mu       sync.Mutex
	facts    *netstate.Facts
	factsErr error
	reverify error
	portal   Portal

	w      *Watcher
	cancel context.CancelFunc
	done   chan error
	exited chan struct{}
}

// netIDOf is the namespace the harness's IDer computes for a gateway.
func netIDOf(gateway string) policy.NetworkID {
	return policy.NetworkID{Kind: "wifi",
		Gateway: netip.MustParseAddr(gateway), GatewayMAC: "aa:bb:cc:dd:ee:ff"}
}

func gw(s string) *netstate.Facts {
	return &netstate.Facts{Uplink: "en0", Gateway: netip.MustParseAddr(s), UplinkMAC: "aa:bb:cc:dd:ee:ff"}
}

func newHarness(t *testing.T, mut func(*Options)) *harness {
	t.Helper()
	h := &harness{
		t:      t,
		clock:  newFakeClock(),
		src:    newChanSource(),
		steps:  make(chan string, 64),
		events: make(chan Event, 64),
		facts:  gw("192.168.1.1"),
	}
	rec := func(format string, a ...any) { h.steps <- fmt.Sprintf(format, a...) }

	o := Options{
		Source: h.src,
		Clock:  h.clock,
		Facts: func(context.Context) (*netstate.Facts, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.facts, h.factsErr
		},
		NetID: func(f *netstate.Facts) policy.NetworkID {
			if f == nil {
				return policy.NetworkID{}
			}
			return policy.NetworkID{Kind: "wifi", Gateway: f.Gateway, GatewayMAC: f.UplinkMAC}
		},
		Initial: netIDOf("192.168.1.1"),
		Handler: Handler{
			Suspend: func(_ context.Context, reason string, _ Event) {
				rec("suspend(%s)", reason)
			},
			Unsuspend: func(_ context.Context, reason string, _ Event) {
				rec("unsuspend(%s)", reason)
			},
			Quiesce:   func(context.Context, Event) { rec("quiesce") },
			Namespace: func(_ context.Context, id policy.NetworkID) { rec("namespace(%s)", id.Key()) },
			Reverify: func(context.Context) error {
				h.mu.Lock()
				err := h.reverify
				h.mu.Unlock()
				rec("reverify")
				return err
			},
			Resume: func(context.Context, Event) { rec("resume") },
			Stop:   func(_ context.Context, _ Event, err error) { rec("stop(%v)", err) },
			Observe: func(ev Event) {
				select {
				case h.events <- ev:
				default:
				}
			},
		},
		Logf: t.Logf,
	}
	if mut != nil {
		mut(&o)
	}
	// A test that swapped the source in keeps driving it through h.src.
	if cs, ok := o.Source.(*chanSource); ok {
		h.src = cs
	}
	w, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.w = w

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	h.exited = make(chan struct{})
	go func() {
		h.done <- w.Run(ctx)
		close(h.exited)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.exited:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})
	// The sleep ticker is armed first thing; wait for it so the first Advance
	// cannot race ahead of the loop.
	h.waitWaiters(1)
	return h
}

// waitWaiters blocks until the watcher has at least n timers armed. The fake
// clock fires only timers that already exist, so advancing before the loop has
// armed one silently does nothing.
func (h *harness) waitWaiters(n int) {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.clock.c.Waiters() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %d armed timer(s); have %d", n, h.clock.c.Waiters())
}

func (h *harness) setFacts(f *netstate.Facts, err error) {
	h.mu.Lock()
	h.facts, h.factsErr = f, err
	h.mu.Unlock()
}

// churn signals the source and drives the debounce window to its end.
func (h *harness) churn() {
	h.t.Helper()
	h.src.signal()
	h.waitWaiters(2) // the sleep ticker plus the debounce timer
	h.clock.c.Advance(DefaultDebounce)
}

func (h *harness) step() string {
	h.t.Helper()
	select {
	case s := <-h.steps:
		return s
	case <-time.After(3 * time.Second):
		h.t.Fatal("timed out waiting for the next handler step")
		return ""
	}
}

// wantSteps asserts the exact sequence of handler calls, in order.
func (h *harness) wantSteps(want ...string) {
	h.t.Helper()
	for i, w := range want {
		if got := h.step(); got != w {
			h.t.Fatalf("step %d = %q, want %q", i, got, w)
		}
	}
}

func (h *harness) noMoreSteps() {
	h.t.Helper()
	select {
	case s := <-h.steps:
		h.t.Fatalf("unexpected extra step %q", s)
	case <-time.After(50 * time.Millisecond):
	}
}

func (h *harness) waitEvent(k Kind) Event {
	h.t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-h.events:
			if ev.Kind == k {
				return ev
			}
		case <-deadline:
			h.t.Fatalf("timed out waiting for a %s event", k)
			return Event{}
		}
	}
}

// TestNetworkChangeSwapsTheNamespaceInOrder is the milestone's central claim:
// a new network quiesces, swaps the verdict namespace, re-verifies the applied
// system state and only then resumes — and the datapath is suspended across
// the whole of it, so no connection is ever judged against the old network's
// cache.
func TestNetworkChangeSwapsTheNamespaceInOrder(t *testing.T) {
	h := newHarness(t, nil)
	before := h.w.NetID()

	h.setFacts(gw("10.0.0.1"), nil)
	h.churn()

	want := netIDOf("10.0.0.1")
	h.wantSteps(
		"suspend("+ReasonSettling+")",
		"quiesce",
		"namespace("+want.Key()+")",
		"reverify",
		"resume",
		"unsuspend("+ReasonSettling+")",
	)
	h.noMoreSteps()

	if got := h.w.NetID(); !got.Equal(want) {
		t.Fatalf("NetID = %s, want %s", got.Key(), want.Key())
	}
	if before.Equal(want) {
		t.Fatal("the test did not actually change the network")
	}
	ev := h.waitEvent(KindNetworkChange)
	if !ev.Prev.Equal(before) || !ev.NetID.Equal(want) {
		t.Fatalf("event carried %s -> %s, want %s -> %s",
			ev.Prev.Key(), ev.NetID.Key(), before.Key(), want.Key())
	}
	if s := h.w.Stats(); s.Settles != 1 {
		t.Fatalf("Settles = %d, want 1", s.Settles)
	}
}

// TestBurstOfChurnSettlesOnce pins the debounce. One network change produces a
// burst of routing messages; re-collecting facts per message would run a dozen
// scutil invocations and swap the namespace repeatedly for one event.
func TestBurstOfChurnSettlesOnce(t *testing.T) {
	h := newHarness(t, nil)
	h.setFacts(gw("10.0.0.1"), nil)

	for i := 0; i < 6; i++ {
		h.src.signal()
	}
	h.waitWaiters(2)
	// Keep the burst inside the window: each signal extends it, so the first
	// advance short of the window must produce nothing.
	h.clock.c.Advance(DefaultDebounce - time.Millisecond)
	h.noMoreSteps()
	h.clock.c.Advance(2 * time.Millisecond)

	h.wantSteps(
		"suspend("+ReasonSettling+")", "quiesce",
		"namespace("+netIDOf("10.0.0.1").Key()+")", "reverify", "resume",
		"unsuspend("+ReasonSettling+")",
	)
	h.noMoreSteps()
	if s := h.w.Stats(); s.Settles != 1 {
		t.Fatalf("a six-message burst produced %d settles, want 1", s.Settles)
	}
}

// TestContinuousChurnStillSettles pins the cap. A link that flaps once a
// second would otherwise postpone the settle forever — starving exactly the
// revalidation the flapping is evidence we need.
func TestContinuousChurnStillSettles(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.Debounce = time.Second
		o.MaxDebounce = 3 * time.Second
	})
	h.setFacts(gw("10.0.0.1"), nil)

	h.src.signal()
	h.waitWaiters(2)
	// Four half-second nudges: each extends the window past the next advance,
	// so only the cap can end it.
	for i := 0; i < 4; i++ {
		h.clock.c.Advance(500 * time.Millisecond)
		h.src.signal()
		time.Sleep(time.Millisecond)
	}
	h.clock.c.Advance(2 * time.Second)
	h.wantSteps("suspend(" + ReasonSettling + ")")
}

// TestSameNetworkOnlyReverifies pins the cheap path: macOS flushes interface
// routes on a link change, so churn on the SAME network still costs a
// re-verify — but nothing is quiesced, no namespace is swapped and no
// connection is held up.
func TestSameNetworkOnlyReverifies(t *testing.T) {
	h := newHarness(t, nil)
	h.churn()
	h.wantSteps("reverify")
	h.noMoreSteps()
	if s := h.w.Stats(); s.Settles != 0 {
		t.Fatalf("Settles = %d, want 0 on an unchanged network", s.Settles)
	}
}

// TestUplinkLostSuspendsAndComingBackLiftsIt is the "fail open and wait"
// branch: with no default route there is nothing to capture and nothing to
// judge, so dpb steps out of the way rather than holding connections open
// against a network that is not there.
func TestUplinkLostSuspendsAndComingBackLiftsIt(t *testing.T) {
	h := newHarness(t, nil)

	h.setFacts(&netstate.Facts{}, nil)
	h.churn()
	h.wantSteps("suspend(" + ReasonUplink + ")")
	h.noMoreSteps()
	if got := h.w.Holds(); len(got) != 1 || got[0] != ReasonUplink {
		t.Fatalf("Holds = %v, want [%s]", got, ReasonUplink)
	}

	// Still down: the hold is taken once, not once per routing message.
	h.churn()
	h.noMoreSteps()

	h.setFacts(gw("192.168.1.1"), nil)
	h.churn()
	h.wantSteps("unsuspend("+ReasonUplink+")", "reverify")
	if got := h.w.Holds(); len(got) != 0 {
		t.Fatalf("Holds = %v after the uplink returned, want none", got)
	}
}

// TestFactsFailureKeepsThePreviousNamespace: an unreadable routing table is
// not evidence that the network changed. Inventing a namespace out of a failed
// read would throw away every verdict learned on the network we are still on.
func TestFactsFailureKeepsThePreviousNamespace(t *testing.T) {
	h := newHarness(t, nil)
	before := h.w.NetID()

	h.setFacts(nil, errors.New("scutil: timed out"))
	h.churn()

	ev := h.waitEvent(KindError)
	if !strings.Contains(ev.Detail, "keeping the current namespace") {
		t.Fatalf("error event detail = %q", ev.Detail)
	}
	h.noMoreSteps()
	if got := h.w.NetID(); !got.Equal(before) {
		t.Fatalf("NetID moved to %s on a failed collection", got.Key())
	}

	// A collection that returns neither facts nor an error is the same thing.
	h.setFacts(nil, nil)
	h.churn()
	h.waitEvent(KindError)
	h.noMoreSteps()
}

// TestReverifyFailureIsReportedNotFatal: a networksetup that refuses must not
// take the watcher down, or the process spends the rest of its life believing
// whatever it believed at start-up.
func TestReverifyFailureIsReportedNotFatal(t *testing.T) {
	h := newHarness(t, nil)
	h.mu.Lock()
	h.reverify = errors.New("networksetup: refused")
	h.mu.Unlock()

	h.churn()
	h.wantSteps("reverify")
	ev := h.waitEvent(KindError)
	if !strings.Contains(ev.Err.Error(), "refused") {
		t.Fatalf("event error = %v", ev.Err)
	}
	// Still watching.
	h.churn()
	h.wantSteps("reverify")
}

// TestFullTunnelVPNStopsARunThatMustCapture is the exit-5 refusal. It is the
// only place in this package that stops the process, and it stops it rather
// than reporting Ready while capturing nothing.
func TestFullTunnelVPNStopsARunThatMustCapture(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.RequireCapture = true })
	f := gw("192.168.1.1")
	f.VPN = netstate.VPNState{Present: true, FullTunnel: true, Iface: "utun6", ServiceName: "Corp"}
	h.setFacts(f, nil)
	h.churn()

	if got := h.step(); !strings.HasPrefix(got, "stop(") {
		t.Fatalf("step = %q, want a stop", got)
	}
	select {
	case err := <-h.done:
		if !errors.Is(err, ErrFullTunnelVPN) {
			t.Fatalf("Run returned %v, want ErrFullTunnelVPN", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after a fatal VPN verdict")
	}
	ev := h.waitEvent(KindVPNFullTunnel)
	if ev.Iface != "utun6" {
		t.Fatalf("the event does not name the tunnel: %+v", ev)
	}
}

// TestFullTunnelVPNIsToleratedByTheProxyFrontEnd: a proxy on loopback keeps
// working underneath any VPN, so refusing to run would be a safety gate firing
// on a configuration that is fine.
func TestFullTunnelVPNIsToleratedByTheProxyFrontEnd(t *testing.T) {
	h := newHarness(t, nil) // RequireCapture is false
	f := gw("192.168.1.1")
	f.VPN = netstate.VPNState{Present: true, FullTunnel: true, Iface: "utun6"}
	h.setFacts(f, nil)
	h.churn()

	h.wantSteps("reverify")
	ev := h.waitEvent(KindVPNFullTunnel)
	if !strings.Contains(ev.Detail, "the proxy still works") {
		t.Fatalf("detail = %q", ev.Detail)
	}
	select {
	case err := <-h.done:
		t.Fatalf("Run returned %v; a full tunnel is not fatal in proxy mode", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestSplitTunnelVPNIsSilent: the wave 1 review's second defect was a rollback
// deleting a coexisting VPN's half-default. A split tunnel must produce no
// action at all.
func TestSplitTunnelVPNIsSilent(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.RequireCapture = true })
	f := gw("192.168.1.1")
	f.VPN = netstate.VPNState{Present: true, Iface: "utun4", ServiceName: "Work"}
	h.setFacts(f, nil)
	h.churn()

	h.wantSteps("reverify")
	h.noMoreSteps()
	select {
	case err := <-h.done:
		t.Fatalf("Run returned %v on a split tunnel", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestSleepIsDetectedAndRevalidates: a lid closing is not a timeout. The
// wall-vs-monotonic divergence is the secondary signal, and it triggers the
// same revalidation the routing churn would.
func TestSleepIsDetectedAndRevalidates(t *testing.T) {
	h := newHarness(t, nil)

	h.clock.sleep(20 * time.Minute)
	h.clock.c.Advance(DefaultSleepTick)

	ev := h.waitEvent(KindWake)
	if ev.Gap < 19*time.Minute {
		t.Fatalf("reported gap %v, want about 20m", ev.Gap)
	}
	h.wantSteps("reverify")
}

// TestOrdinaryTicksAreNotSleep pins that a running machine's 5 s ticker does
// not revalidate every five seconds.
func TestOrdinaryTicksAreNotSleep(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i < 3; i++ {
		h.clock.c.Advance(DefaultSleepTick)
		h.waitWaiters(1)
	}
	h.noMoreSteps()
}

// scriptedProber returns whatever the test currently wants.
type scriptedProber struct {
	mu sync.Mutex
	p  Portal
	n  int
}

func (s *scriptedProber) Probe(context.Context) Portal {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return s.p
}

func (s *scriptedProber) set(p Portal) {
	s.mu.Lock()
	s.p = p
	s.mu.Unlock()
}

// TestPortalSuspendsAndClearsOnItsOwn is the hotel-network story: dpb steps
// out of the way so the login page loads, polls, and comes back by itself.
func TestPortalSuspendsAndClearsOnItsOwn(t *testing.T) {
	sp := &scriptedProber{p: Portal{Behind: true, Detail: "intercepted"}}
	h := newHarness(t, func(o *Options) { o.Portal = sp })

	h.churn()
	h.wantSteps("reverify", "suspend("+ReasonPortal+")")
	if got := h.w.Holds(); len(got) != 1 || got[0] != ReasonPortal {
		t.Fatalf("Holds = %v, want [%s]", got, ReasonPortal)
	}
	if !h.w.Portal().Behind {
		t.Fatal("the watcher does not report the portal")
	}

	// The poll while suspended must not re-suspend or thrash.
	h.waitWaiters(2) // the sleep ticker plus the portal poll
	h.clock.c.Advance(DefaultPortalPoll)
	h.noMoreSteps()

	sp.set(Portal{Behind: false, Detail: "cleared"})
	h.waitWaiters(2)
	h.clock.c.Advance(DefaultPortalPoll)
	h.wantSteps("unsuspend("+ReasonPortal+")", "reverify")
	if got := h.w.Holds(); len(got) != 0 {
		t.Fatalf("Holds = %v after the portal cleared", got)
	}
	h.waitEvent(KindPortalCleared)
}

// TestInconclusivePortalProbeNeverSuspends: absence of evidence is not a
// portal. A probe that could not reach anything must leave dpb doing its job,
// or a user who walks out of Wi-Fi range finds the bypass switched off.
func TestInconclusivePortalProbeNeverSuspends(t *testing.T) {
	sp := &scriptedProber{p: Portal{Err: errors.New("no route to host")}}
	h := newHarness(t, func(o *Options) { o.Portal = sp })

	h.churn()
	h.wantSteps("reverify")
	h.noMoreSteps()
	if got := h.w.Holds(); len(got) != 0 {
		t.Fatalf("an inconclusive probe took the holds %v", got)
	}
}

// TestPortalHoldOutlivesTheSettleThatFoundIt pins the release order: the
// settling hold is released last, so a portal found during a settle is still
// suspending the datapath when the settle finishes.
func TestPortalHoldOutlivesTheSettleThatFoundIt(t *testing.T) {
	sp := &scriptedProber{p: Portal{Behind: true, Detail: "intercepted"}}
	h := newHarness(t, func(o *Options) { o.Portal = sp })
	h.setFacts(gw("10.0.0.1"), nil)
	h.churn()

	h.wantSteps(
		"suspend("+ReasonSettling+")", "quiesce",
		"namespace("+netIDOf("10.0.0.1").Key()+")", "reverify",
		"suspend("+ReasonPortal+")", "resume",
		"unsuspend("+ReasonSettling+")",
	)
	if got := h.w.Holds(); len(got) != 1 || got[0] != ReasonPortal {
		t.Fatalf("Holds = %v, want the portal hold to survive the settle", got)
	}
}

// TestSourceFailureIsRetried: losing the routing socket costs the primary
// signal, not the watcher. It reports, waits and re-opens.
func TestSourceFailureIsRetried(t *testing.T) {
	src := newChanSource()
	src.err = errors.New("routing socket closed")
	h := newHarness(t, func(o *Options) { o.Source = src })

	ev := h.waitEvent(KindError)
	if !strings.Contains(ev.Detail, "re-opening") {
		t.Fatalf("detail = %q", ev.Detail)
	}
	<-src.runs // the first, failing Run
	h.waitWaiters(2)
	h.clock.c.Advance(DefaultSourceRetry)
	select {
	case <-src.runs:
	case <-time.After(3 * time.Second):
		t.Fatal("the source was never re-opened")
	}
	// And it works again.
	h.churn()
	h.wantSteps("reverify")
}

func TestNewRejectsAnUnusableConfiguration(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrNoFacts) {
		t.Fatalf("New with no Facts = %v, want ErrNoFacts", err)
	}
	f := func(context.Context) (*netstate.Facts, error) { return nil, nil }
	if _, err := New(Options{Facts: f}); !errors.Is(err, ErrNoNetID) {
		t.Fatalf("New with no NetID = %v, want ErrNoNetID", err)
	}
	w, err := New(Options{
		Facts: f,
		NetID: func(*netstate.Facts) policy.NetworkID { return policy.NetworkID{} },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if w.o.Debounce != DefaultDebounce || w.o.SleepGap != DefaultSleepGap {
		t.Fatalf("zero durations were not defaulted: %+v", w.o)
	}
	// A MaxDebounce below Debounce would make the cap fire before the window,
	// defeating the debounce entirely.
	w2, err := New(Options{
		Facts: f, NetID: func(*netstate.Facts) policy.NetworkID { return policy.NetworkID{} },
		Debounce: time.Second, MaxDebounce: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if w2.o.MaxDebounce < w2.o.Debounce {
		t.Fatalf("MaxDebounce %v is below Debounce %v", w2.o.MaxDebounce, w2.o.Debounce)
	}
}

// TestRunWithNoHandlerDoesNotPanic: every hook is optional, and a caller that
// only wants events must not have to write six empty functions.
func TestRunWithNoHandlerDoesNotPanic(t *testing.T) {
	src := newChanSource()
	w, err := New(Options{
		Source: src,
		Clock:  newFakeClock(),
		Facts:  func(context.Context) (*netstate.Facts, error) { return gw("10.0.0.1"), nil },
		NetID: func(f *netstate.Facts) policy.NetworkID {
			return policy.NetworkID{Kind: "wifi", Gateway: f.Gateway}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	src.signal()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestKindString(t *testing.T) {
	for k := KindRouteChange; k <= KindError; k++ {
		if s := k.String(); s == "" || strings.HasPrefix(s, "kind(") {
			t.Errorf("Kind(%d).String() = %q", k, s)
		}
	}
	if s := Kind(99).String(); s != "kind(99)" {
		t.Errorf("unknown kind = %q", s)
	}
}

func TestReasonText(t *testing.T) {
	for _, r := range []string{ReasonSettling, ReasonUplink, ReasonPortal} {
		if ReasonText(r) == r {
			t.Errorf("ReasonText(%q) returned the identifier, not a sentence", r)
		}
	}
	if ReasonText("something else") != "something else" {
		t.Error("an unknown reason should pass through")
	}
}

func TestEventString(t *testing.T) {
	e := Event{Kind: KindNetworkChange, Detail: "moved", Err: errors.New("boom")}
	s := e.String()
	for _, want := range []string{"network-change", "moved", "boom"} {
		if !strings.Contains(s, want) {
			t.Errorf("Event.String() = %q, want it to contain %q", s, want)
		}
	}
}

// TestPortalProbeIsRateLimitedOnTheCheapPath: routing churn that does not
// change the network still costs a re-verify, but three HTTP requests per
// burst of kernel messages would make dpb the noisiest client on the network
// for no new information.
func TestPortalProbeIsRateLimitedOnTheCheapPath(t *testing.T) {
	sp := &scriptedProber{p: Portal{Detail: "clean"}}
	h := newHarness(t, func(o *Options) { o.Portal = sp })

	h.churn()
	h.wantSteps("reverify")
	h.churn()
	h.wantSteps("reverify")
	if got := h.w.Stats().Probes; got != 1 {
		t.Fatalf("two same-network churns cost %d canary probes, want 1", got)
	}

	// A NEW network forces one, because that is exactly when the answer can
	// have changed.
	h.setFacts(gw("10.0.0.1"), nil)
	h.churn()
	h.wantSteps("suspend("+ReasonSettling+")", "quiesce",
		"namespace("+netIDOf("10.0.0.1").Key()+")", "reverify", "resume",
		"unsuspend("+ReasonSettling+")")
	if got := h.w.Stats().Probes; got != 2 {
		t.Fatalf("a network change cost %d total probes, want 2", got)
	}
}
