//go:build !windows

// This file contains tests for network watching that use startRun(),
// which requires Unix process spawning for the janitor.

package cliapp

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/netwatch"
	"github.com/mumudevx/dpb/internal/paths"
	"github.com/mumudevx/dpb/internal/policy"
)

// loggingGlobals is a globals whose warnings land in a buffer.
func loggingGlobals() (*globals, *bytes.Buffer) {
	var buf bytes.Buffer
	return &globals{env: Env{Stdout: &buf, Stderr: &buf}}, &buf
}

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

// TestDpbOnDoesNotLiftACaptivePortalSuspension: the manual lever and the
// automatic holds are separate on purpose. `dpb on` must not put dpb back in
// the path of the login page the user is trying to load.
func TestDpbOnDoesNotLiftACaptivePortalSuspension(t *testing.T) {
	var ks killSwitch
	ks.set(true, "`dpb off`")
	ks.hold(netwatch.ReasonPortal, netwatch.ReasonText(netwatch.ReasonPortal))

	if !ks.suspended() {
		t.Fatal("both levers are set and the switch is not suspended")
	}
	ks.set(false, "") // `dpb on`
	if !ks.suspended() {
		t.Fatal("`dpb on` lifted a captive-portal hold it cannot see the reason for")
	}
	suspended, why := ks.state()
	if !suspended || !strings.Contains(why, "captive portal") {
		t.Fatalf("state = (%v, %q)", suspended, why)
	}

	ks.release(netwatch.ReasonPortal)
	if ks.suspended() {
		t.Fatal("releasing the last hold left the switch suspended")
	}
	if _, why := ks.state(); why != "" {
		t.Fatalf("a switch that is on still reports %q", why)
	}
}

// TestHoldsAreASetNotACounter: a repeated event must not need a matching
// number of releases, or one extra routing message leaves dpb suspended.
func TestHoldsAreASetNotACounter(t *testing.T) {
	var ks killSwitch
	ks.hold(netwatch.ReasonUplink, "gone")
	ks.hold(netwatch.ReasonUplink, "gone")
	ks.release(netwatch.ReasonUplink)
	if ks.suspended() {
		t.Fatal("two holds needed two releases")
	}
}

// TestKillSwitchReasonsAreOrdered pins that `dpb status` does not reshuffle
// its reason line between two reads of the same state.
func TestKillSwitchReasonsAreOrdered(t *testing.T) {
	var ks killSwitch
	ks.set(true, "`dpb off`")
	ks.hold(netwatch.ReasonSettling, netwatch.ReasonText(netwatch.ReasonSettling))
	ks.hold(netwatch.ReasonPortal, netwatch.ReasonText(netwatch.ReasonPortal))
	ks.hold(netwatch.ReasonUplink, netwatch.ReasonText(netwatch.ReasonUplink))

	_, first := ks.state()
	for i := 0; i < 20; i++ {
		if _, again := ks.state(); again != first {
			t.Fatalf("the reason line changed between reads:\n%q\n%q", first, again)
		}
	}
	want := []string{"uplink", "portal", "changed"}
	at := -1
	for _, w := range want {
		i := strings.Index(first, w)
		if i < 0 || i < at {
			t.Fatalf("reason %q is missing or out of order in %q", w, first)
		}
		at = i
	}
}

func TestNetIDBoxSwaps(t *testing.T) {
	var b netIDBox
	if !b.get().IsZero() {
		t.Fatal("a fresh box is not the zero namespace")
	}
	id := policy.NetworkID{Kind: "wifi", Gateway: netip.MustParseAddr("10.0.0.1")}
	b.set(id)
	if !b.get().Equal(id) {
		t.Fatalf("get = %s, want %s", b.get().Key(), id.Key())
	}
}

// TestObserveNetwatchNamesTheLoginPage: a portal warning whose remediation
// does not say where to log in leaves the user with nowhere to go.
func TestObserveNetwatchNamesTheLoginPage(t *testing.T) {
	g, buf := loggingGlobals()
	observeNetwatch(g, netwatch.Event{
		Kind:   netwatch.KindPortalDetected,
		Detail: "a.example answered 302",
		Portal: netwatch.Portal{Behind: true, LoginURL: "http://portal.example/login"},
	})
	if s := buf.String(); !strings.Contains(s, "http://portal.example/login") {
		t.Fatalf("the warning does not name the login page:\n%s", s)
	}

	g, buf = loggingGlobals()
	observeNetwatch(g, netwatch.Event{Kind: netwatch.KindPortalDetected, Detail: "no location"})
	if s := buf.String(); !strings.Contains(s, "captive.apple.com") {
		t.Fatalf("a portal with no Location left the user with no next step:\n%s", s)
	}

	g, buf = loggingGlobals()
	observeNetwatch(g, netwatch.Event{Kind: netwatch.KindUplinkLost})
	if s := buf.String(); !strings.Contains(s, "uplink") {
		t.Fatalf("the uplink warning says nothing about the uplink:\n%s", s)
	}

	// Everything else is debug detail, not a warning.
	g, buf = loggingGlobals()
	observeNetwatch(g, netwatch.Event{Kind: netwatch.KindNetworkChange, Detail: "moved"})
	observeNetwatch(g, netwatch.Event{Kind: netwatch.KindWake, Gap: time.Minute})
	if buf.Len() != 0 {
		t.Fatalf("an ordinary event was printed as a warning:\n%s", buf)
	}
}

// TestRequiresCaptureIsFalseInProxyMode pins the safety gate's scope: a proxy
// on loopback keeps working underneath a full-tunnel VPN, so refusing to run
// would be the gate firing on a configuration that is fine. --tun is the one
// thing that flips it, and --allow-vpn deliberately does not: it overrides the
// start-up refusal, not the mid-run one.
func TestRequiresCaptureIsFalseInProxyMode(t *testing.T) {
	if requiresCapture(runFlags{}) {
		t.Fatal("proxy mode claims it needs to own routes")
	}
	if !requiresCapture(runFlags{tun: true}) {
		t.Fatal("--tun does not require capture, so the full-tunnel-VPN gate is dead again")
	}
	if !requiresCapture(runFlags{tun: true, allowVPN: true}) {
		t.Fatal("--allow-vpn disarmed the watcher's mid-run VPN gate")
	}
}

// TestNotesCopyDoesNotAliasTheLiveState guards the one place a handler
// running on the watcher's goroutine reads state the control socket writes.
func TestNotesCopyDoesNotAliasTheLiveState(t *testing.T) {
	l := &liveState{}
	l.setNotes([]string{"one"})
	c := l.notesCopy()
	c[0] = "two"
	if _, notes := l.systemReport(); notes[0] != "one" {
		t.Fatalf("notesCopy aliased the live state: %v", notes)
	}
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
