//go:build !windows

// The three tests here drive a whole `dpb run` through startRun/startRunTweak,
// which spawn fakeDPBBinary — a /bin/sh script standing in for the dpb
// executable the janitor child is spawned from — so they carry the same tag
// as run_test.go, where startRun is defined. See netwatchrun_test.go for the
// network-watching tests that need no running process at all.

package cliapp

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/netwatch"
	"github.com/mumudevx/dpb/internal/paths"
)

// scriptedSource is a routing-change source a test drives by hand.
type scriptedSource struct{ ch chan struct{} }

func newScriptedSource() *scriptedSource {
	return &scriptedSource{ch: make(chan struct{}, 8)}
}

func (s *scriptedSource) Run(ctx context.Context, out chan<- struct{}) error {
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

func (s *scriptedSource) signal() { s.ch <- struct{}{} }

// movingFacts is a machine that can be carried to another network.
type movingFacts struct {
	mu sync.Mutex
	f  *netstate.Facts
}

func (m *movingFacts) get(context.Context, netstate.Env) *netstate.Facts {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.f
}

func (m *movingFacts) move(gateway, mac string) {
	m.mu.Lock()
	m.f = &netstate.Facts{
		Uplink: "en0", Services: []string{"Wi-Fi"},
		Gateway: netip.MustParseAddr(gateway), UplinkMAC: mac,
	}
	m.mu.Unlock()
}

// scriptedPortal is a captive-portal verdict a test sets.
type scriptedPortal struct {
	mu sync.Mutex
	p  netwatch.Portal
}

func (s *scriptedPortal) Probe(context.Context) netwatch.Portal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p
}

func (s *scriptedPortal) set(p netwatch.Portal) {
	s.mu.Lock()
	s.p = p
	s.mu.Unlock()
}

// TestNetworkChangeSwapsTheReportedNamespace is M15's acceptance clause, run
// against a whole `dpb run` rather than against the watcher alone: moving to
// another network must change the namespace `dpb status --json` reports, or
// the tool is still serving a strategy learned on somebody else's ISP.
func TestNetworkChangeSwapsTheReportedNamespace(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	src := newScriptedSource()
	mf := &movingFacts{}
	mf.move("192.168.1.1", "aa:bb:cc:dd:ee:ff")

	h := startRunTweak(t, newFakeMac(), layout, func(g *globals) {
		g.factsFn = mf.get
		g.netwatchOpts = func(o *netwatch.Options) { o.Source = src; o.Portal = inertProber{} }
	}, "--proxy-style", "none")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	before, err := liveClient(t, layout).Status(ctx)
	if err != nil {
		t.Fatalf("status: %v\nbanner:\n%s", err, h.out)
	}
	if before.NetworkID == "" {
		t.Fatal("the run reports no network identity at all")
	}

	// The laptop moves: a different gateway on a different router.
	mf.move("10.42.0.1", "11:22:33:44:55:66")
	src.signal()

	deadline := time.Now().Add(15 * time.Second)
	var after string
	for time.Now().Before(deadline) {
		st, err := liveClient(t, layout).Status(ctx)
		if err == nil && st.NetworkID != before.NetworkID {
			after = st.NetworkID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if after == "" {
		t.Fatalf("the namespace stayed %s after the network changed", before.NetworkID)
	}

	// And it is not suspended afterwards: the settle takes a hold and gives it
	// back, so a laptop that changed networks is doing its job again.
	st, err := liveClient(t, layout).Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Suspended {
		t.Fatalf("the run stayed suspended after the settle: %q", st.SuspendReason)
	}
}

// TestCaptivePortalSuspendsAndTheStatusSaysWhy is the hotel-network clause:
// dpb steps out of the way, the PAC renders all-DIRECT, and `dpb status` says
// what happened rather than leaving the user with a network that half works.
func TestCaptivePortalSuspendsAndTheStatusSaysWhy(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	src := newScriptedSource()
	mf := &movingFacts{}
	mf.move("192.168.1.1", "aa:bb:cc:dd:ee:ff")
	sp := &scriptedPortal{p: netwatch.Portal{
		Behind: true, Reason: "intercepted", LoginURL: "http://portal.example/login",
		Detail: "a.example answered 302 instead of the expected 204",
	}}

	h := startRunTweak(t, newFakeMac(), layout, func(g *globals) {
		g.factsFn = mf.get
		g.netwatchOpts = func(o *netwatch.Options) {
			o.Source = src
			o.Portal = sp
			// The shipped poll is 15 s; a test cannot wait that long to see
			// dpb come back by itself, and the interval is not what is under
			// test — the resume is.
			o.PortalPoll = 100 * time.Millisecond
		}
	}, "--proxy-style", "none")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mf.move("10.42.0.1", "11:22:33:44:55:66") // joining the hotel's network
	src.signal()

	// The predicate names the portal rather than merely "suspended": the
	// settle takes its own hold first, and matching that one would assert
	// nothing about the portal at all.
	st := awaitStatus(t, ctx, layout, func(s observStatus) bool {
		return s.Suspended && strings.Contains(s.SuspendReason, "captive portal")
	})
	if !strings.Contains(st.SuspendReason, "captive portal") {
		t.Fatalf("SuspendReason = %q, want it to name the portal", st.SuspendReason)
	}
	// The served PAC is what macOS actually reads, and it must be all-DIRECT.
	if body := fetchDirect(t, "http://"+h.addr()+"/dpb.pac"); !strings.Contains(body, "DIRECT") ||
		strings.Contains(body, "PROXY") {
		t.Fatalf("the PAC served while suspended is not all-DIRECT:\n%s", body)
	}

	// The portal clears; dpb comes back by itself.
	sp.set(netwatch.Portal{Detail: "3 of 3 connectivity canaries answered correctly"})
	src.signal()
	st = awaitStatus(t, ctx, layout, func(s observStatus) bool { return !s.Suspended })
	if st.Suspended {
		t.Fatal("dpb stayed suspended after the portal cleared")
	}
}

// TestNetwatchStopsBeforeTheSystemSettingsComeOff pins the teardown order. A
// watcher still running while UndoAll reverts would see its own settings
// disappear from the RIB and put every one of them straight back, leaving the
// user's proxy pane pointing at a listener that has closed.
func TestNetwatchStopsBeforeTheSystemSettingsComeOff(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	h := startRun(t, newFakeMac(), layout, "-v", "--proxy-style", "pac")
	h.shutdown(t)
	assertTeardownOrder(t, h.errOut.String(),
		"stop the network watcher", "revert system settings")
}

// ── helpers ────────────────────────────────────────────────────────────────

// observStatus is the slice of observ.Status awaitStatus predicates read.
type observStatus struct {
	Suspended     bool
	SuspendReason string
	NetworkID     string
}

func awaitStatus(t *testing.T, ctx context.Context, layout paths.Layout,
	ok func(observStatus) bool) observStatus {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last observStatus
	for time.Now().Before(deadline) {
		st, err := liveClient(t, layout).Status(ctx)
		if err == nil {
			last = observStatus{
				Suspended: st.Suspended, SuspendReason: st.SuspendReason, NetworkID: st.NetworkID,
			}
			if ok(last) {
				return last
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the run never reached the expected state; last was %+v", last)
	return last
}
