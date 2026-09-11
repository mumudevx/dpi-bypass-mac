// This file contains tests for network watching that do not need a running
// `dpb run` process: they drive the watcher's own types (killSwitch, netIDBox,
// observeNetwatch) directly. See netwatchrun_startrun_test.go for the ones
// that do — those need startRun/startRunTweak, which spawn fakeDPBBinary, a
// /bin/sh script, and so carry that file's tag instead.

package cliapp

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netwatch"
	"github.com/mumudevx/dpb/internal/policy"
)

// loggingGlobals is a globals whose warnings land in a buffer.
func loggingGlobals() (*globals, *bytes.Buffer) {
	var buf bytes.Buffer
	return &globals{env: Env{Stdout: &buf, Stderr: &buf}}, &buf
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
