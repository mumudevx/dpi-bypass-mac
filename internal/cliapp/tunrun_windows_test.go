//go:build windows

package cliapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/netstate"
)

// TestTunDefaultsToOffAndNamesTheAdapterOnWindows is
// tunrun_unix_test.go's TestTunDefaultsToOffInTheParsedFlags for this
// platform's adapter naming.
//
// The first half is the same on both and is the one that matters most: --tun
// must default to OFF, because proxy mode needs no elevation and
// MEASUREMENTS.md §3 records the unprivileged emitters beating this DPI, so a
// --tun that defaulted on would charge every user administrator rights for
// coverage most of them do not need.
//
// The second half is where the platforms part. "utun" with no unit means "the
// kernel picks one" on darwin; on Windows there is no unit allocator and the
// name is what the user sees in Network Connections, so tunname_windows.go
// defaults to "dpb" and validateTunName refuses "utun" outright. Pinning the
// parsed default rather than the help text means a change of wording cannot
// hide a change of behaviour — and pinning it HERE means a change of platform
// default cannot hide behind the darwin assertion either.
func TestTunDefaultsToOffAndNamesTheAdapterOnWindows(t *testing.T) {
	t.Parallel()
	g := &globals{env: Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}}
	cmd := newRunCmd(g)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v, _ := cmd.Flags().GetBool("tun"); v {
		t.Fatal("--tun defaults to on; proxy mode must stay the default")
	}
	v, _ := cmd.Flags().GetString("tun-name")
	if v != "dpb" {
		t.Fatalf("--tun-name defaults to %q, want dpb so the adapter is findable in "+
			"Network Connections", v)
	}
	// And the default has to be a name this platform's own validator accepts:
	// a default the very next check rejects would make `dpb run --tun` fail
	// for everybody who did not pass the flag.
	if err := validateTunName(v); err != nil {
		t.Fatalf("the default --tun-name %q is refused by validateTunName: %v", v, err)
	}
}

// TestTunDryRunOpensNoAdapterAndStillPrintsThePlan is
// tunrun_unix_test.go's TestTunDryRunOpensNoDeviceAndStillPrintsThePlan with
// this platform's adapter name.
//
// --dry-run is the one thing an unprivileged user can usefully do with --tun,
// so it must produce the REAL Op sequence — the ordering is the part that is
// hard to get right and the part worth reading — while opening no adapter,
// which would be a mutation and would need elevation.
//
// The last assertion is the only line that differs, and it has to: with no
// adapter there is no name to read back off a device, so the plan names the
// one that was ASKED for, and --tun-name's default is "dpb" here and "utun"
// there. validateTunName on each platform rejects the other's, so no shared
// literal exists.
func TestTunDryRunOpensNoAdapterAndStillPrintsThePlan(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{args: []string{"--dry-run"}, noDevice: true})
	defer fx.stop()

	if fx.opened {
		t.Fatal("--dry-run opened an adapter; that is a mutation and it needs elevation")
	}
	want := []netstate.OpKind{
		netstate.OpIfconfig, netstate.OpRoute, netstate.OpRoute,
		netstate.OpRoute, netstate.OpRoute, netstate.OpDNSServers,
	}
	got := fx.seq.kinds()
	if len(got) != len(want) {
		t.Fatalf("--dry-run planned %d Op(s), want %d:\n  %s",
			len(got), len(want), strings.Join(fx.seq.describe(), "\n  "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Op %d is %s, want %s\n  %s", i, got[i], want[i],
				strings.Join(fx.seq.describe(), "\n  "))
		}
	}
	if d := fx.seq.describe(); !strings.Contains(d[0], "dpb ") {
		t.Fatalf("--dry-run's plan does not name the requested adapter: %s", d[0])
	}
}
