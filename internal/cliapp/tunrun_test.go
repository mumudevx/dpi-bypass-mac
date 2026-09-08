package cliapp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/front/tunfe"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/netwatch"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/ops"
	"github.com/mumudevx/dpb/internal/paths"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/testnet"
)

// These tests exist because internal/front/tunfe was 712 lines of tested code
// that the shipped binary could not reach: `go list -deps ./cmd/dpb` did not
// name it, nothing outside the package imported it, and `dpb run --help` had no
// tun option at all. A milestone is not done when its package is tested; it is
// done when the binary can use it. Everything below drives the COMMAND, or the
// functions the command calls, and never tunfe on its own.
//
// None of this needs root or a utun. The device is a tunfe.PipeLink — the
// shipped netstack over an in-memory link, not a stub of it — and the system
// mutations go through a sequencer that records the Ops instead of applying
// them, because the ifconfig Op verifies through net.Interfaces() and there is
// no interface here to find.

// ── the mode selector ───────────────────────────────────────────────────────

// TestRunOffersTheTunFlags is the "is it wired at all" gate. Before this lane
// `dpb run --help` listed no tun option and `go list -deps ./cmd/dpb | grep -c
// front/tunfe` printed 0.
func TestRunOffersTheTunFlags(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), Env{
		Args:   []string{"run", "--help"},
		Stdout: &out,
		Stderr: &errOut,
	})
	if code != ExitOK {
		t.Fatalf("run --help exited %d\n%s", code, errOut.String())
	}
	help := out.String()
	for _, flag := range []string{"--tun ", "--tun-name", "--mtu", "--allow-vpn", "--set-dns"} {
		if !strings.Contains(help, flag) {
			t.Errorf("`dpb run --help` does not offer %s:\n%s", flag, help)
		}
	}
	// Proxy stays the default. MEASUREMENTS.md §3 records the unprivileged
	// emitters beating this DPI, so a --tun that defaulted on would charge
	// every user root for coverage most of them do not need.
	if !strings.Contains(help, "requires root") {
		t.Errorf("--tun does not say it needs root:\n%s", help)
	}
}

// TestTunDefaultsToOffInTheParsedFlags pins the default itself rather than the
// help text, so a change of wording cannot hide a change of behaviour.
func TestTunDefaultsToOffInTheParsedFlags(t *testing.T) {
	t.Parallel()
	g := &globals{env: Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}}
	cmd := newRunCmd(g)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v, _ := cmd.Flags().GetBool("tun"); v {
		t.Fatal("--tun defaults to on; proxy mode must stay the default")
	}
	if v, _ := cmd.Flags().GetString("tun-name"); v != "utun" {
		t.Fatalf("--tun-name defaults to %q, want utun so the kernel picks the unit", v)
	}
}

// ── exit code 4: needs root ─────────────────────────────────────────────────

// TestTunWithoutRootIsExitFour drives the whole command. ExitNeedRoot is a
// published contract the LaunchAgent branches on (docs/PLAN.md amendment A10),
// so the code matters as much as the message.
func TestTunWithoutRootIsExitFour(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = false

	g := &globals{
		env:    Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		layout: &layout,
		runner: newFakeMac(),
		rib:    newFakeMac(),
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--tun", "--proxy-style", "none",
		"--port", "0", "--socks-port", fmt.Sprint(freePort(t))})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("dpb run --tun succeeded unprivileged")
	}
	if got := exitCodeFor(err); got != ExitNeedRoot {
		t.Fatalf("exit code %d, want %d (ExitNeedRoot)", got, ExitNeedRoot)
	}
	// "It failed" is not a remediation. The message has to name the command
	// that works and the one that needs no root at all.
	msg := err.Error()
	for _, want := range []string{"sudo dpb run --tun", "--dry-run"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the needs-root message does not mention %q:\n%s", want, msg)
		}
	}
}

// TestTunDryRunNeedsNoRoot: --dry-run applies nothing, so it needs nothing, and
// inspecting what --tun would change must not itself require sudo.
func TestTunDryRunNeedsNoRoot(t *testing.T) {
	t.Parallel()
	unpriv := paths.Layout{Elevated: false}
	if err := requireRootForTun(unpriv, true); err != nil {
		t.Fatalf("--tun --dry-run demanded root: %v", err)
	}
	if err := requireRootForTun(unpriv, false); err == nil {
		t.Fatal("--tun without --dry-run did not demand root")
	}
	if err := requireRootForTun(paths.Layout{Elevated: true}, false); err != nil {
		t.Fatalf("--tun under root was refused: %v", err)
	}
}

// ── exit code 5: the full-tunnel VPN refusal ────────────────────────────────

// TestTunRefusesUnderAFullTunnelVPN reaches the gate M15 built and could not
// test, because --tun did not exist: netwatch.ErrFullTunnelVPN and exit 5.
func TestTunRefusesUnderAFullTunnelVPN(t *testing.T) {
	t.Parallel()
	full := &netstate.Facts{
		Uplink:  "en0",
		Gateway: netip.MustParseAddr("192.0.2.1"),
		VPN:     netstate.VPNState{Present: true, FullTunnel: true, Iface: "utun3", ServiceName: "Mullvad"},
	}
	split := &netstate.Facts{
		Uplink: "en0",
		VPN:    netstate.VPNState{Present: true, FullTunnel: false, Iface: "utun3"},
	}

	err := refuseFullTunnelVPN(full, true, false)
	if err == nil {
		t.Fatal("--tun started under a full-tunnel VPN")
	}
	if !errors.Is(err, netwatch.ErrFullTunnelVPN) {
		t.Fatalf("the refusal does not wrap ErrFullTunnelVPN: %v", err)
	}
	if got := exitCodeFor(err); got != ExitRefused {
		t.Fatalf("exit code %d, want %d (ExitRefused)", got, ExitRefused)
	}
	if !strings.Contains(err.Error(), "without --tun") {
		t.Errorf("the refusal does not offer the mode that works underneath a VPN:\n%v", err)
	}

	// Proxy mode keeps working underneath a full tunnel: a browser reaches
	// 127.0.0.1 without consulting the default route at all.
	if err := refuseFullTunnelVPN(full, false, false); err != nil {
		t.Fatalf("proxy mode was refused under a VPN: %v", err)
	}
	// A split tunnel leaves the default alone, so both our scoped default and
	// our capture routes still work.
	if err := refuseFullTunnelVPN(split, true, false); err != nil {
		t.Fatalf("--tun was refused under a SPLIT tunnel: %v", err)
	}
	// The override exists and is honoured.
	if err := refuseFullTunnelVPN(full, true, true); err != nil {
		t.Fatalf("--allow-vpn did not override the refusal: %v", err)
	}
}

// TestTunRunRefusesUnderAFullTunnelVPN is the same rule through the command, so
// the gate cannot be correct in a helper and unreachable from `dpb run`.
func TestTunRunRefusesUnderAFullTunnelVPN(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = true
	mac := newFakeMac()
	g := &globals{
		env:    Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		layout: &layout,
		runner: mac,
		rib:    mac,
		facts: &netstate.Facts{
			Uplink:  "en0",
			Gateway: netip.MustParseAddr("192.0.2.1"),
			VPN:     netstate.VPNState{Present: true, FullTunnel: true, Iface: "utun9"},
		},
		getenv: func(string) string { return "" },
		// If the refusal did not fire, this would be asked for a device.
		openLink: func(string, int, func(string, ...any)) (tunfe.Link, error) {
			t.Error("a utun was opened under a full-tunnel VPN")
			return nil, errors.New("refused")
		},
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--tun", "--proxy-style", "none",
		"--port", "0", "--socks-port", fmt.Sprint(freePort(t))})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	if got := exitCodeFor(err); got != ExitRefused {
		t.Fatalf("exit code %d (err %v), want %d", got, err, ExitRefused)
	}
}

// ── the smaller decisions ───────────────────────────────────────────────────

// TestSetDNSDefaultsOffInProxyModeAndOnUnderTun pins docs/PLAN.md's CLI table.
func TestSetDNSDefaultsOffInProxyModeAndOnUnderTun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tun     bool
		flag    string
		want    bool
		wantErr bool
	}{
		{tun: false, flag: "", want: false},
		{tun: true, flag: "", want: true},
		{tun: true, flag: "off", want: false},
		{tun: true, flag: "on", want: true},
		{tun: false, flag: "on", wantErr: true},
		{tun: true, flag: "maybe", wantErr: true},
	} {
		got, err := resolveSetDNS(tc.tun, tc.flag)
		if tc.wantErr {
			if err == nil {
				t.Errorf("resolveSetDNS(%v, %q) accepted it", tc.tun, tc.flag)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveSetDNS(%v, %q): %v", tc.tun, tc.flag, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveSetDNS(%v, %q) = %v, want %v", tc.tun, tc.flag, got, tc.want)
		}
	}
}

// TestTunNeedsAnUplinkToEscapeThrough. The capture routes cover the whole
// address space, so a run with nowhere to pin its own sockets would build a
// tunnel that eats its own upstream traffic.
func TestTunNeedsAnUplinkToEscapeThrough(t *testing.T) {
	t.Parallel()
	if _, err := tunUplink(nil); err == nil {
		t.Fatal("--tun accepted a machine with no facts at all")
	}
	if _, err := tunUplink(&netstate.Facts{}); err == nil {
		t.Fatal("--tun accepted a machine with no uplink")
	}
	got, err := tunUplink(&netstate.Facts{Uplink: "en0"})
	if err != nil || got != "en0" {
		t.Fatalf("tunUplink = %q, %v", got, err)
	}
}

// TestCapturesV6IsFailClosed. Opening the IPv6 gate is the resolver's licence
// to hand applications AAAA records, so it may only open where there is a v6
// path to protect them with.
func TestCapturesV6IsFailClosed(t *testing.T) {
	t.Parallel()
	v6 := netip.MustParseAddr("2001:db8::1")
	if capturesV6(nil) {
		t.Error("no facts at all read as an IPv6 uplink")
	}
	if capturesV6(&netstate.Facts{V6Global: []netip.Addr{v6}}) {
		t.Error("a v6 address with no v6 gateway read as a capturable path")
	}
	if capturesV6(&netstate.Facts{GatewayV6: v6}) {
		t.Error("a v6 gateway with no global address read as a capturable path")
	}
	if !capturesV6(&netstate.Facts{GatewayV6: v6, V6Global: []netip.Addr{v6}}) {
		t.Error("a dual-stack machine was not offered IPv6 capture")
	}
}

// TestTunResolverListKeepsTheOriginalsBehindUs. The plan rejected fail-closed
// DNS outright: a SIGKILLed dpb must degrade to plaintext in one RTT, not to no
// DNS at all on a banking laptop.
func TestTunResolverListKeepsTheOriginalsBehindUs(t *testing.T) {
	t.Parallel()
	got := tunResolverList([]netip.Addr{
		netip.MustParseAddr("192.0.2.53"),
		netip.MustParseAddr("2001:db8::53"),
	})
	if len(got) < 2 || got[0] != tunLocal {
		t.Fatalf("the tunnel is not first in %v", got)
	}
	if got[1] != "192.0.2.53" {
		t.Fatalf("the machine's own resolver is not the fallback: %v", got)
	}
}

// ── bring-up ordering, teardown ordering ────────────────────────────────────

// TestTunBringUpAppliesTheOrderedSequence is the one that matters most.
//
// docs/PLAN.md data path F: configure the interface, scope a default route to
// the real uplink so our own sockets can still escape, START THE DATAPATH, then
// install the capture routes, then host routes for the machine's own
// nameservers, then point the resolvers at the tunnel. Every one of those steps
// is a netstate Op, journalled and verified, and not a shell-out — macOS
// route(8) reports failure with exit status 0.
func TestTunBringUpAppliesTheOrderedSequence(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{})
	defer fx.stop()

	want := []netstate.OpKind{
		netstate.OpIfconfig,   // the device, before anything names it
		netstate.OpRoute,      // 0.0.0.0/0 via the gateway, scoped to the uplink
		netstate.OpRoute,      // 0.0.0.0/1  -interface <tun>
		netstate.OpRoute,      // 128.0.0.0/1
		netstate.OpRoute,      // <nameserver>/32
		netstate.OpDNSServers, // the services point at the tunnel
	}
	got := fx.seq.kinds()
	if len(got) != len(want) {
		t.Fatalf("bring-up applied %d Op(s):\n  %s\nwant %d", len(got), strings.Join(fx.seq.describe(), "\n  "), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Op %d is %s, want %s\n  %s", i, got[i], want[i], strings.Join(fx.seq.describe(), "\n  "))
		}
	}

	// The command passes a REAL start function, and the datapath actually comes
	// up. Where inside the sequence BringUp calls it — between the escape route
	// and the capture routes, so the capture routes never point at nothing and
	// our own sockets never loop — is tunfe.TestBringUpOrdering's contract, and
	// asserting the count here would be a race against the supervisor
	// goroutine rather than a second check of the same thing. newTunFixture has
	// already waited for it.

	// The interface name comes from the DEVICE, never from --tun-name: the
	// kernel picks the unit for "utun", and a route naming the requested name
	// would name an interface that does not exist.
	d := fx.seq.describe()
	if !strings.Contains(d[0], fx.link.name()) {
		t.Fatalf("the ifconfig Op names %q, want the device's own name %q", d[0], fx.link.name())
	}
	if !strings.Contains(d[0], tunLocal) || !strings.Contains(d[0], tunPeer) {
		t.Fatalf("the utun has no point-to-point pair: %s", d[0])
	}
	if !strings.Contains(d[1], tunFixtureUplink) {
		t.Fatalf("the escape route is not scoped to the uplink: %s", d[1])
	}
	if !strings.Contains(d[2], "0.0.0.0/1") || !strings.Contains(d[3], "128.0.0.0/1") {
		t.Fatalf("the capture pair is not the two halves of the address space: %s / %s", d[2], d[3])
	}
	if !strings.Contains(d[4], "192.168.0.1/32") {
		t.Fatalf("the machine's own resolver is not routed into the tunnel: %s", d[4])
	}
	// The tunnel first, the machine's own resolvers behind it: fail-OPEN.
	if !strings.Contains(d[5], tunLocal+" 192.168.0.1") {
		t.Fatalf("the resolver list is not tunnel-then-originals: %s", d[5])
	}

	// And every one of them is REPORTED. The banner promises "Ctrl-C reverts
	// every change above"; a route it does not list is a change the user was
	// never told about and cannot check afterwards.
	if len(fx.applied) != len(d) {
		t.Fatalf("the banner would list %d of %d applied changes: %v", len(fx.applied), len(d), fx.applied)
	}
	for _, want := range []string{"0.0.0.0/1", "128.0.0.0/1", "192.168.0.1/32", tunLocal} {
		if !strings.Contains(strings.Join(fx.applied, "\n"), want) {
			t.Errorf("the banner does not report %s among the applied changes: %v", want, fx.applied)
		}
	}
}

// TestTunSetDNSOffLeavesTheResolverListAlone. The host routes still capture the
// resolvers the machine already names, so DNS is still ours; what is skipped is
// the mutation of the user's service configuration.
func TestTunSetDNSOffLeavesTheResolverListAlone(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{args: []string{"--set-dns", "off"}})
	defer fx.stop()

	for _, k := range fx.seq.kinds() {
		if k == netstate.OpDNSServers {
			t.Fatalf("--set-dns off still rewrote the resolver list:\n  %s",
				strings.Join(fx.seq.describe(), "\n  "))
		}
	}
	var sawHostRoute bool
	for _, d := range fx.seq.describe() {
		if strings.Contains(d, "192.168.0.1/32") {
			sawHostRoute = true
		}
	}
	if !sawHostRoute {
		t.Fatalf("--set-dns off also dropped the nameserver capture route:\n  %s",
			strings.Join(fx.seq.describe(), "\n  "))
	}
	if !fx.hasNote("--set-dns off") {
		t.Errorf("the banner does not say the resolver list was left alone: %v", fx.notes)
	}
}

// TestTunTeardownRevertsBeforeTheDeviceCloses. macOS `route delete` naming a
// closed interface fails — and reports that failure with exit status 0 — so the
// device must be the LAST thing to go.
func TestTunTeardownRevertsBeforeTheDeviceCloses(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{})
	fx.stop()

	if fx.seq.undone == 0 {
		t.Fatal("teardown never reverted the tunnel's system state")
	}
	if fx.link.closedAt.IsZero() {
		t.Fatal("teardown never closed the utun; the device would outlive the process's file descriptor")
	}
	if !fx.link.closedAt.After(fx.seq.undoneAt) {
		t.Fatalf("the device closed at %s, before UndoAll at %s: every route delete naming it "+
			"would fail, and route(8) would report that failure as success",
			fx.link.closedAt, fx.seq.undoneAt)
	}
}

// TestTunBringUpUnwindsAPartialFailure. A route that will not install must not
// leave the three that did behind, and the failure has to reach the user as a
// failure rather than as a banner.
func TestTunBringUpUnwindsAPartialFailure(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{
		failAt:     3, // the first capture route, after ifconfig and the scoped default
		expectFail: true,
	})
	if fx.err == nil {
		t.Fatal("a failed capture route was reported as a successful bring-up")
	}
	if fx.seq.undone == 0 {
		t.Fatal("a half-installed capture was left on the machine")
	}
	if fx.link.closedAt.IsZero() {
		t.Fatal("the utun was left open after a failed bring-up")
	}
}

// ── the Ops are real netstate Ops ───────────────────────────────────────────

// TestTunRouteOpsApplyAndRevertThroughNetstate takes the Ops the command built
// and runs them through a real netstate.Manager against internal/testnet's
// fakes, so "journalled through netstate" is a property of the objects rather
// than of a comment.
func TestTunRouteOpsApplyAndRevertThroughNetstate(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{})
	built := fx.seq.applied()
	fx.stop()

	rib := testnet.NewRIB()
	runner := testnet.NewScriptRunner()
	runner.Fallback(func(argv []string) netstate.Result {
		// route(8) on macOS prints "add net ...: gateway ... " and exits 0
		// whether or not the route landed, which is the whole reason netstate
		// verifies against the RIB instead of the exit status. This fake keeps
		// that property and mirrors the effect into the RIB.
		res := netstate.Result{Argv: argv}
		if len(argv) < 4 || argv[0] != "route" {
			return res
		}
		r, ok := parseRouteArgv(argv)
		if !ok {
			return res
		}
		switch r.verb {
		case "add":
			rib.Add(netstate.RouteEntry{Dst: r.dst, Gateway: r.gw, Iface: r.iface, Scoped: r.scoped})
		case "delete":
			rib.Remove(r.dst, "")
		}
		return res
	})

	journal := openTempJournal(t)
	mgr := netstate.NewManager(journal, netstate.Env{Runner: runner, RIB: rib, Logf: t.Logf})

	ctx := context.Background()
	var applied int
	for _, op := range built {
		if op.Kind() != netstate.OpRoute {
			continue
		}
		if err := mgr.Do(ctx, op); err != nil {
			t.Fatalf("apply %s through netstate: %v", op.Describe(), err)
		}
		applied++
	}
	if applied < 4 {
		t.Fatalf("only %d route Op(s) were built; want the scoped default, both halves and a nameserver", applied)
	}
	routes, _ := rib.Routes()
	if len(routes) != applied {
		t.Fatalf("the RIB holds %d route(s) after %d applies", len(routes), applied)
	}

	if errs := mgr.UndoAll(ctx); len(errs) > 0 {
		t.Fatalf("UndoAll: %v", errs)
	}
	routes, _ = rib.Routes()
	if len(routes) != 0 {
		t.Fatalf("teardown left %d route(s) behind: %v", len(routes), routes)
	}
}

// ── one decision path, one exclusion set ────────────────────────────────────

// TestTunSharesEveryDecisionObjectWithProxyMode.
//
// Losing exclusions in TUN mode was a real defect in the previous
// implementation: a flow arrives at a transparent front end as a bare address,
// so the ONLY thing that can turn it back into the name a bypass rule was
// written against is the reverse map the DNS answers were learned into. If any
// of these six were a fresh object, the tunnel would be judging with a
// different ladder, a different verdict cache or an empty exclusion set.
func TestTunSharesEveryDecisionObjectWithProxyMode(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{})
	defer fx.stop()

	o := tunOptions(fx.g, fx.cfg, fx.sub, nil, tunfe.DefaultMTU)
	if o.Ladder != fx.sub.runner {
		t.Error("the tunnel has a ladder runner of its own, so it can reach a different verdict than the proxy")
	}
	if o.Scope != fx.sub.scope {
		t.Error("the tunnel has a scope engine of its own, so a `dpb scope` rule would not reach it")
	}
	if o.Reverse != fx.sub.reverse {
		t.Error("the tunnel has a reverse map of its own, so a DNS-learned name cannot re-attach to a captured flow")
	}
	if o.DNS != fx.sub.dns {
		t.Error("the tunnel has a resolver of its own")
	}
	if o.Sender != fx.sub.sender {
		t.Error("the tunnel has a sender of its own, so the process-wide small-write governor guards half the writes")
	}
	if o.UDPDial != fx.sub.udpDial {
		t.Error("the tunnel has a UDP dialer of its own")
	}
}

// TestTunPinsEverySocketOfItsOwnToTheUplink.
//
// Under --tun the capture routes cover the whole address space. An unpinned
// socket is routed back into our own netstack — and for the chain's plaintext
// DNS rungs that is not a detour but unbounded recursion, because the tunnel
// answers UDP/53 out of the same chain that asked.
func TestTunPinsEverySocketOfItsOwnToTheUplink(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{})
	defer fx.stop()

	if got := fx.sub.udpDial.(*flow.NetUDPDialer).Interface; got != tunFixtureUplink {
		t.Errorf("the UDP dialer is pinned to %q, want %s", got, tunFixtureUplink)
	}
	if got := fx.sub.dial.(*flow.NetDialer).Interface; got != tunFixtureUplink {
		t.Errorf("the stream dialer is pinned to %q, want %s", got, tunFixtureUplink)
	}

	// Proxy mode leaves both on the system's routing decision, which is the
	// correct answer there: it installs no capture routes at all.
	psub := fx.proxySubsystems(t)
	if got := psub.dial.(*flow.NetDialer).Interface; got != "" {
		t.Errorf("proxy mode pinned its dialer to %q; nothing there needs escaping", got)
	}
}

// TestUplinkDialFuncRefusesAName is the MEASUREMENTS.md §5.4 rule at the one
// new dial site this lane adds. A hostname reaching a dialler is how the first
// compatibility matrix scored every emitter 0/6 against the BTK sinkhole.
func TestUplinkDialFuncRefusesAName(t *testing.T) {
	t.Parallel()
	d := uplinkDialFunc("lo0", t.Logf)
	if _, err := d(context.Background(), "tcp", "cloudflare-dns.com:443"); err == nil {
		t.Fatal("the uplink dialler accepted a hostname")
	} else if !strings.Contains(err.Error(), "cloudflare-dns.com") {
		t.Fatalf("the refusal does not name what it refused: %v", err)
	}
}

// ── the datapath, end to end over an in-memory device ───────────────────────

// TestTunAnswersDNSInProcessAndKeepsTheExclusion is the whole point of the lane
// in one test.
//
// A DNS query is written into the tunnel as a raw IP packet. It must be
// answered IN PROCESS — relaying it would hand the ISP's resolver exactly the
// queries DoH exists to hide — and the answer must land in the reverse map, so
// that the flow which follows a moment later, arriving as a bare address with
// no name attached, is still recognised as the host the user excluded.
func TestTunAnswersDNSInProcessAndKeepsTheExclusion(t *testing.T) {
	t.Parallel()
	const name = "excluded.example"
	answer := netip.MustParseAddr("203.0.113.9")
	resolver := startFakeResolver(t, answer)

	fx := newTunFixture(t, tunFixtureOptions{
		args: []string{"--dns-udp", resolver, "--bypass", name},
	})
	defer fx.stop()

	src := netip.AddrPortFrom(netip.MustParseAddr(tunPeer), 40000)
	dst := netip.AddrPortFrom(netip.MustParseAddr(tunLocal), 53)
	query, err := testnet.DNSQuery(src, dst, 0x4242, name)
	if err != nil {
		t.Fatalf("build the query: %v", err)
	}
	if err := fx.peer.writePacket(query); err != nil {
		t.Fatalf("write the query into the tunnel: %v", err)
	}

	reply, err := fx.peer.readPacket(20 * time.Second)
	if err != nil {
		t.Fatalf("the tunnel never answered UDP/53: %v", err)
	}
	if len(reply) < 20+8+12 {
		t.Fatalf("the reply is %d bytes, too short to be a DNS answer", len(reply))
	}
	// It came back from the address the query was sent to, over UDP, from
	// port 53. That is an answer, not a relayed packet on its way out.
	if reply[9] != 17 {
		t.Fatalf("the reply is IP protocol %d, want 17 (UDP)", reply[9])
	}
	ihl := int(reply[0]&0x0f) * 4
	if sport := binary.BigEndian.Uint16(reply[ihl : ihl+2]); sport != 53 {
		t.Fatalf("the reply came from port %d, want 53", sport)
	}
	if id := binary.BigEndian.Uint16(reply[ihl+8 : ihl+10]); id != 0x4242 {
		t.Fatalf("the reply carries transaction id %#x, want 0x4242", id)
	}

	// The name is attached to the address before the reply goes out, so the
	// TCP flow that follows already knows what it is talking to.
	got, ok := fx.sub.reverse.Lookup(answer)
	if !ok || got != name {
		t.Fatalf("the reverse map holds %q (%v) for %s; a captured flow to that address "+
			"would arrive unnamed and the user's exclusion would be lost", got, ok, answer)
	}
	// And the exclusion the user typed is what that name resolves to in the
	// scope engine both front ends share.
	if v := fx.sub.scope.ForName(name, 443); v.Class != policy.ScopeBypass {
		t.Fatalf("%s is %s under --tun, want %s", name, v.Class, policy.ScopeBypass)
	}
}

// TestTunAppearsInTheBanner: a user who ran with sudo has to be able to see
// which device was opened, because that is the name every recovery command
// (`ifconfig`, `route delete`) needs.
func TestTunAppearsInTheBanner(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{})
	defer fx.stop()

	var found bool
	for _, l := range fx.listeners {
		if l.Kind == "tun" && l.Addr == fx.link.name() {
			found = true
		}
	}
	if !found {
		t.Fatalf("the tunnel is not among the reported listeners: %v", fx.listeners)
	}
}

// TestTunDryRunOpensNoDeviceAndStillPrintsThePlan.
//
// --dry-run is the one thing an unprivileged user can usefully do with --tun,
// so it must produce the REAL Op sequence — the ordering is the part that is
// hard to get right and the part worth reading — while opening no utun, which
// would be a mutation and would need root.
func TestTunDryRunOpensNoDeviceAndStillPrintsThePlan(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{args: []string{"--dry-run"}, noDevice: true})
	defer fx.stop()

	if fx.opened {
		t.Fatal("--dry-run opened a utun; that is a mutation and it needs root")
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
	// With no device there is no kernel-assigned name, so the plan names the
	// device that was ASKED for and says so by using it consistently.
	if d := fx.seq.describe(); !strings.Contains(d[0], "utun ") {
		t.Fatalf("--dry-run's plan does not name the requested device: %s", d[0])
	}
}

// TestTunCapturesIPv6OnlyWithAPathToProtectItWith.
//
// The IPv6 gate is the resolver's licence to hand applications AAAA records.
// DOSSIER GT19 records an IPv6 sinkhole registered to BTK itself, so answering
// AAAA for traffic nothing is carrying is a silent leak, not a convenience.
func TestTunCapturesIPv6OnlyWithAPathToProtectItWith(t *testing.T) {
	t.Parallel()

	v4only := newTunFixture(t, tunFixtureOptions{})
	defer v4only.stop()
	if v4only.sub.v6gate.Captured() {
		t.Error("a v4-only tunnel opened the IPv6 gate; AAAA would be answered for traffic nothing carries")
	}
	for _, d := range v4only.seq.describe() {
		if strings.Contains(d, "::/1") {
			t.Errorf("a v4-only machine got an IPv6 capture route: %s", d)
		}
	}
	if !v4only.hasNote("IPv6 is not captured") {
		t.Errorf("the banner does not say IPv6 is unprotected: %v", v4only.notes)
	}

	dual := newTunFixture(t, tunFixtureOptions{v6: true})
	defer dual.stop()
	if !dual.sub.v6gate.Captured() {
		t.Fatal("a dual-stack tunnel left the IPv6 gate shut after verifying both capture routes")
	}
	var sawV6Addr, sawHalves int
	for _, d := range dual.seq.describe() {
		if strings.Contains(d, tunLocalV6) {
			sawV6Addr++
		}
		if strings.Contains(d, "::/1") || strings.Contains(d, "8000::/1") {
			sawHalves++
		}
	}
	if sawV6Addr == 0 {
		t.Error("the utun got no IPv6 address")
	}
	if sawHalves != 2 {
		t.Errorf("the IPv6 capture pair is %d route(s), want ::/1 and 8000::/1:\n  %s",
			sawHalves, strings.Join(dual.seq.describe(), "\n  "))
	}

	// Teardown shuts the gate before a single route is deleted: from then on
	// nothing this process answers may hand out an address nothing is carrying.
	dual.stop()
	if dual.sub.v6gate.Captured() {
		t.Fatal("the IPv6 gate stayed open after the tunnel came down")
	}
}

// TestRunStartsAndTearsDownTheTunnel drives the SHIPPED command from the
// command line down, which is the only thing that proves `dpb run --tun` — not
// startTun, not tunfe — brings a tunnel up and takes it away again.
func TestRunStartsAndTearsDownTheTunnel(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = true

	seq := &recordingSeq{started: make(chan struct{})}
	dev, _ := tunfe.NewPipe(tunfe.DefaultMTU)
	// The kernel picks the unit for "utun", which is what --tun-name defaults
	// to, so every Op naming utun7 proves the name was read back off the
	// device rather than copied from the flag.
	dev.SetName("utun7")
	link := &spyLink{Link: dev, seq: seq}

	// watchFacts is the collector the network watcher re-runs on every routing
	// change. See the SelfIface assertion below.
	var (
		watchFacts func(context.Context) (*netstate.Facts, error)
		seenSelf   struct {
			sync.Mutex
			iface string
		}
	)

	h := startRunTweak(t, newFakeMac(), layout, func(g *globals) {
		facts := &netstate.Facts{
			Uplink:   tunFixtureUplink,
			Gateway:  netip.MustParseAddr("192.0.2.1"),
			Services: []string{"Wi-Fi"},
		}
		g.facts = facts
		g.factsFn = func(_ context.Context, e netstate.Env) *netstate.Facts {
			seenSelf.Lock()
			seenSelf.iface = e.SelfIface
			seenSelf.Unlock()
			return facts
		}
		g.openLink = func(string, int, func(string, ...any)) (tunfe.Link, error) { return link, nil }
		g.tunSeq = func(tunfe.Sequencer) tunfe.Sequencer { return seq }
		g.netwatchOpts = func(o *netwatch.Options) {
			o.Source = inertSource{}
			o.Portal = inertProber{}
			watchFacts = o.Facts
		}
	}, "--tun", "--proxy-style", "none")

	seq.awaitStart(t)
	if kinds := seq.kinds(); len(kinds) == 0 || kinds[0] != netstate.OpIfconfig {
		t.Fatalf("`dpb run --tun` applied %v; want the interface first", kinds)
	}
	if d := seq.describe(); !strings.Contains(d[0], "utun7") {
		t.Fatalf("the Ops name the requested device rather than the one the kernel gave us: %s", d[0])
	}
	// The banner names the device, because that is the name every recovery
	// command a user might have to type by hand needs.
	if out := h.out.String(); !strings.Contains(out, "tun") || !strings.Contains(out, link.name()) {
		t.Fatalf("the banner does not name the tunnel:\n%s", out)
	}

	// The watcher has to know which utun is OURS. Our capture routes are the
	// 0.0.0.0/1 + 128.0.0.0/1 pair a WireGuard-style VPN installs, so without
	// this the first routing change after bring-up classifies dpb as a
	// full-tunnel VPN and dpb refuses to run alongside itself with exit 5.
	if watchFacts == nil {
		t.Fatal("the network watcher was never given a facts collector")
	}
	if _, err := watchFacts(context.Background()); err != nil {
		t.Fatalf("re-collect facts: %v", err)
	}
	seenSelf.Lock()
	self := seenSelf.iface
	seenSelf.Unlock()
	if self != link.name() {
		t.Fatalf("the watcher re-collects facts with SelfIface=%q, want %q", self, link.name())
	}

	h.shutdown(t)
	if seq.undone == 0 {
		t.Fatal("`dpb run --tun` exited without reverting the tunnel's system state")
	}
	if link.closedAt.IsZero() {
		t.Fatal("`dpb run --tun` exited without closing the utun")
	}
	if !link.closedAt.After(seq.undoneAt) {
		t.Fatal("the utun closed before the routes naming it were deleted")
	}
}

// TestTunDeviceFailureBringsTheRunDown.
//
// A read error on the utun is not recoverable: the capture routes still point
// at the device, so a process that logged it and carried on would be a
// blackhole printing "Ready". The previous implementation's bare `return` in
// the read loop is exactly that failure, and this is the wiring that makes the
// surfaced error reach the process.
func TestTunDeviceFailureBringsTheRunDown(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = true

	seq := &recordingSeq{started: make(chan struct{})}
	dev, _ := tunfe.NewPipe(tunfe.DefaultMTU)
	dev.SetName("utun7")
	link := &spyLink{Link: dev, seq: seq}

	h := startRunTweak(t, newFakeMac(), layout, func(g *globals) {
		g.facts = &netstate.Facts{
			Uplink:   tunFixtureUplink,
			Gateway:  netip.MustParseAddr("192.0.2.1"),
			Services: []string{"Wi-Fi"},
		}
		g.openLink = func(string, int, func(string, ...any)) (tunfe.Link, error) { return link, nil }
		g.tunSeq = func(tunfe.Sequencer) tunfe.Sequencer { return seq }
	}, "--tun", "--proxy-style", "none")

	seq.awaitStart(t)
	h.stopped = true // this run is expected to end by itself, with an error
	dev.FailRead(errors.New("the device went away"))

	select {
	case err := <-h.done:
		if err == nil {
			t.Fatal("a dead utun left `dpb run --tun` reporting success")
		}
		if !strings.Contains(err.Error(), "tunnel datapath") {
			t.Fatalf("the failure does not name the tunnel: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("`dpb run --tun` kept running over a device that reads nothing")
	}
	if seq.undone == 0 {
		t.Error("the capture routes were left behind after the device failed")
	}
}

// ── the fixture ─────────────────────────────────────────────────────────────

// tunFixtureUplink is the interface the fixture's machine escapes through. It
// is a real one because IP_BOUND_IF is real.
const tunFixtureUplink = "lo0"

type tunFixtureOptions struct {
	args []string
	// v6 gives the fixture's machine a working IPv6 uplink to escape through.
	v6 bool
	// noDevice expects no utun to be opened at all, which is --dry-run.
	noDevice bool
	// failAt makes the Nth Op (1-based) fail, modelling a route that will not
	// install.
	failAt     int
	expectFail bool
}

// tunFixture is `dpb run --tun` with the two things that need root replaced:
// the utun is a tunfe.PipeLink, and the netstate.Manager is wrapped by a
// recorder. Everything between them is the shipped code.
type tunFixture struct {
	t         *testing.T
	g         *globals
	cfg       *config.Loaded
	sub       *subsystems
	seq       *recordingSeq
	link      *spyLink
	peer      *pipePeer
	listeners []listener
	applied   []string
	notes     []string
	err       error
	opened    bool

	st       *stack
	stopOnce sync.Once
}

func newTunFixture(t *testing.T, o tunFixtureOptions) *tunFixture {
	t.Helper()
	ops.Install()

	layout := tempLayout(t)
	layout.Elevated = true
	if err := layout.EnsureDirs(); err != nil {
		t.Fatalf("state dirs: %v", err)
	}

	mac := newFakeMac()
	// A machine with one uplink, one gateway and one resolver of its own.
	//
	// The uplink is lo0 rather than a made-up name because it has to be a
	// REAL interface: under --tun every socket dpb opens for itself is pinned
	// to it with IP_BOUND_IF, and the fixture's fake resolver is on loopback.
	// That is the recursion guard under test, not scenery.
	facts := &netstate.Facts{
		Uplink:   tunFixtureUplink,
		Gateway:  netip.MustParseAddr("192.0.2.1"),
		Services: []string{"Wi-Fi"},
	}
	if o.v6 {
		facts.GatewayV6 = netip.MustParseAddr("2001:db8::1")
		facts.V6Global = []netip.Addr{netip.MustParseAddr("2001:db8::1234")}
	}

	g := &globals{
		env:    Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		layout: &layout,
		runner: mac,
		rib:    mac,
		facts:  facts,
		getenv: func(string) string { return "" },
	}

	fx := &tunFixture{t: t, g: g, st: &stack{}}
	fx.seq = &recordingSeq{failAt: o.failAt, started: make(chan struct{})}

	dev, peer := tunfe.NewPipe(tunfe.DefaultMTU)
	// The kernel picks the unit. --tun-name stays "utun" below, so every Op
	// naming this device proves the name was read back off it.
	dev.SetName("utun7")
	fx.link = &spyLink{Link: dev, seq: fx.seq}
	fx.peer = &pipePeer{link: peer}
	g.openLink = func(string, int, func(string, ...any)) (tunfe.Link, error) {
		fx.opened = true
		return fx.link, nil
	}

	// The command's own flag parsing, so the fixture cannot disagree with the
	// binary about what --tun means.
	cmd := newRunCmd(g)
	args := append([]string{"--tun", "--proxy-style", "none",
		"--port", "0", "--socks-port", fmt.Sprint(freePort(t))}, o.args...)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	f := runFlagsOf(t, cmd)

	cfg, err := loadConfig(g, layout, cmd, f)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	fx.cfg = cfg
	ladder, err := cfg.LadderSpecs()
	if err != nil {
		t.Fatalf("ladder: %v", err)
	}

	env := netstate.Env{Runner: mac, RIB: mac, Facts: facts, Logf: t.Logf}
	counters := observ.NewCounters(observ.CountersOptions{})
	sub, err := buildSubsystems(g, layout, cfg, ladder, env, "", counters, &killSwitch{}, true)
	if err != nil {
		t.Fatalf("build subsystems: %v", err)
	}
	fx.sub = sub

	// The same two steps runRun takes, in the same order: --set-dns is
	// resolved (and refused, if it is invalid for this mode) before startTun
	// is entered at all.
	setDNS, err := resolveSetDNS(f.tun, f.setDNS)
	if err != nil {
		t.Fatalf("resolve --set-dns: %v", err)
	}
	half, applied, notes, err := startTun(context.Background(), g, cfg, f, setDNS, sub, fx.seq, env, fx.st)
	fx.err = err
	fx.applied = applied
	fx.notes = notes
	if err != nil {
		if !o.expectFail {
			t.Fatalf("startTun: %v", err)
		}
		// The teardown step was pushed before bring-up started, which is what
		// unwinds a partial apply. Drain it here so the assertions can read it.
		fx.stop()
		return fx
	}
	if o.expectFail {
		t.Fatal("the injected failure did not stop bring-up")
	}
	if !o.noDevice {
		fx.seq.awaitStart(t)
	}
	fx.listeners = []listener{{Kind: "tun", Addr: half.iface}}
	return fx
}

func (fx *tunFixture) stop() {
	fx.stopOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), teardownBudget)
		defer cancel()
		if err := fx.st.drain(ctx, fx.t.Logf); err != nil {
			fx.t.Logf("teardown: %v", err)
		}
		_ = fx.sub.store.Close()
	})
}

func (fx *tunFixture) hasNote(sub string) bool {
	for _, n := range fx.notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// proxySubsystems builds the same subsystems with --tun off, so a test can
// assert the difference rather than assert an absolute.
func (fx *tunFixture) proxySubsystems(t *testing.T) *subsystems {
	t.Helper()
	layout := tempLayout(t)
	if err := layout.EnsureDirs(); err != nil {
		t.Fatalf("state dirs: %v", err)
	}
	mac := newFakeMac()
	env := netstate.Env{Runner: mac, RIB: mac, Facts: fx.g.facts, Logf: t.Logf}
	ladder, err := fx.cfg.LadderSpecs()
	if err != nil {
		t.Fatalf("ladder: %v", err)
	}
	sub, err := buildSubsystems(fx.g, layout, fx.cfg, ladder, env, "",
		observ.NewCounters(observ.CountersOptions{}), &killSwitch{}, false)
	if err != nil {
		t.Fatalf("build proxy subsystems: %v", err)
	}
	t.Cleanup(func() { _ = sub.store.Close() })
	return sub
}

// runFlagsOf reads the parsed flags back off the command. newRunCmd binds them
// into a runFlags the closure owns, so this is how a test gets the same value
// RunE would have been handed.
func runFlagsOf(t *testing.T, cmd *cobra.Command) runFlags {
	t.Helper()
	var f runFlags
	fl := cmd.Flags()
	f.tun, _ = fl.GetBool("tun")
	f.tunName, _ = fl.GetString("tun-name")
	f.mtu, _ = fl.GetInt("mtu")
	f.allowVPN, _ = fl.GetBool("allow-vpn")
	f.setDNS, _ = fl.GetString("set-dns")
	f.dryRun, _ = fl.GetBool("dry-run")
	f.proxyStyle, _ = fl.GetString("proxy-style")
	f.port, _ = fl.GetInt("port")
	f.socksPort, _ = fl.GetInt("socks-port")
	f.bypass, _ = fl.GetStringSlice("bypass")
	f.dnsUDP, _ = fl.GetStringSlice("dns-udp")
	return f
}

// ── the recording sequencer ─────────────────────────────────────────────────

// recordingSeq stands in for netstate.Manager.
//
// It records rather than applies because the ifconfig Op verifies through
// net.Interfaces() and there is no interface on this machine to find — the
// device under test is an in-memory pipe. What the Ops DO is netstate's own
// tested behaviour; what this asserts is that `dpb run --tun` builds the right
// ones, in the right order, and hands them to a sequencer rather than shelling
// out.
type recordingSeq struct {
	started      chan struct{}
	mu           sync.Mutex
	ops          []netstate.Op
	undone       int
	undoneAt     time.Time
	startedAfter int
	failAt       int
}

func (r *recordingSeq) Do(_ context.Context, op netstate.Op) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, op)
	if r.failAt > 0 && len(r.ops) == r.failAt {
		return fmt.Errorf("injected failure applying %s", op.Describe())
	}
	return nil
}

func (r *recordingSeq) UndoAll(context.Context) []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.undone++
	r.undoneAt = time.Now()
	return nil
}

// mark records how many Ops had been applied when the datapath started, and
// releases the fixture, which must not assert on an ordering the supervisor
// goroutine has not reached yet.
func (r *recordingSeq) mark() {
	r.mu.Lock()
	r.startedAfter = len(r.ops)
	r.mu.Unlock()
	close(r.started)
}

// awaitStart blocks until the datapath supervisor is running.
func (r *recordingSeq) awaitStart(t *testing.T) {
	t.Helper()
	select {
	case <-r.started:
	case <-time.After(20 * time.Second):
		t.Fatal("the tunnel datapath never started")
	}
}

func (r *recordingSeq) startedAfterOps() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.startedAfter
}

func (r *recordingSeq) applied() []netstate.Op {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]netstate.Op(nil), r.ops...)
}

func (r *recordingSeq) kinds() []netstate.OpKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]netstate.OpKind, 0, len(r.ops))
	for _, op := range r.ops {
		out = append(out, op.Kind())
	}
	return out
}

func (r *recordingSeq) describe() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.ops))
	for _, op := range r.ops {
		out = append(out, op.Describe())
	}
	return out
}

// ── the device ──────────────────────────────────────────────────────────────

// spyLink is a PipeLink that records when it was closed, so the teardown order
// — every route gone before the device — is assertable.
type spyLink struct {
	tunfe.Link
	seq      *recordingSeq
	mu       sync.Mutex
	closedAt time.Time
	devName  string
	events   int
}

// Events is called exactly once, by tunfe.Server.Serve, which is the datapath
// coming up. Recording the Op count at that moment is how the ordering rule —
// nothing is captured before something is listening behind it, and nothing is
// captured before our own escape route exists — becomes assertable.
func (s *spyLink) Events() <-chan tunfe.Event {
	s.mu.Lock()
	first := s.events == 0
	s.events++
	s.mu.Unlock()
	if first && s.seq != nil {
		s.seq.mark()
	}
	return s.Link.Events()
}

func (s *spyLink) name() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.devName == "" {
		n, _ := s.Link.Name()
		s.devName = n
	}
	return s.devName
}

func (s *spyLink) Close() error {
	s.mu.Lock()
	if s.closedAt.IsZero() {
		s.closedAt = time.Now()
	}
	s.mu.Unlock()
	return s.Link.Close()
}

// pipePeer is the other end of the in-memory device: what a program on this
// machine would see if its packets were routed into the tunnel.
type pipePeer struct{ link *tunfe.PipeLink }

func (p *pipePeer) writePacket(pkt []byte) error {
	buf := make([]byte, tunfe.LinkOffset+len(pkt))
	copy(buf[tunfe.LinkOffset:], pkt)
	_, err := p.link.Write([][]byte{buf}, tunfe.LinkOffset)
	return err
}

func (p *pipePeer) readPacket(within time.Duration) ([]byte, error) {
	type result struct {
		pkt []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, tunfe.LinkOffset+2048)
		sizes := make([]int, 1)
		n, err := p.link.Read([][]byte{buf}, sizes, tunfe.LinkOffset)
		if err != nil {
			ch <- result{err: err}
			return
		}
		if n == 0 {
			ch <- result{err: errors.New("no packet")}
			return
		}
		out := make([]byte, sizes[0])
		copy(out, buf[tunfe.LinkOffset:tunfe.LinkOffset+sizes[0]])
		ch <- result{pkt: out}
	}()
	select {
	case r := <-ch:
		return r.pkt, r.err
	case <-time.After(within):
		return nil, errors.New("timed out")
	}
}

// ── the fake resolver ───────────────────────────────────────────────────────

// startFakeResolver answers A queries with one address and AAAA queries with an
// empty NOERROR, over plaintext UDP on loopback. It is what --dns-udp prepends,
// so the chain answers without reaching the network.
func startFakeResolver(t *testing.T, answer netip.Addr) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake resolver: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := dnsAnswer(buf[:n], answer)
			if resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// dnsAnswer builds a reply to query: one A record for an A question, an empty
// NOERROR for anything else. The question section is echoed verbatim, so the
// name encoding is whatever the chain sent.
func dnsAnswer(query []byte, answer netip.Addr) []byte {
	if len(query) < 12+5 {
		return nil
	}
	question := query[12:]
	if len(question) < 4 {
		return nil
	}
	qtype := binary.BigEndian.Uint16(question[len(question)-4 : len(question)-2])

	out := make([]byte, 12)
	copy(out[0:2], query[0:2])
	binary.BigEndian.PutUint16(out[2:4], 0x8180) // QR, RD, RA, NOERROR
	binary.BigEndian.PutUint16(out[4:6], 1)      // one question
	out = append(out, question...)

	if qtype != 1 || !answer.Is4() {
		return out
	}
	binary.BigEndian.PutUint16(out[6:8], 1) // one answer
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	v4 := answer.As4()
	out = append(out, rr...)
	return append(out, v4[:]...)
}

// ── small helpers ───────────────────────────────────────────────────────────

// parsedRoute is a route(8) command line, read back.
type parsedRoute struct {
	verb   string
	dst    netip.Prefix
	gw     netip.Addr
	iface  string
	scoped bool
}

// parseRouteArgv reads the argv netstate's route Op builds.
//
// -ifscope and -interface are deliberately NOT collapsed: RTF_IFSCOPE is part
// of a route's identity in the RIB, and a fake that reported a scoped add as an
// unscoped entry would let the very failure netstate verifies against — an
// -ifscope add that silently landed unscoped — pass this test.
func parseRouteArgv(argv []string) (parsedRoute, bool) {
	var r parsedRoute
	v6 := false
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "route", "-n":
		case "add", "delete":
			r.verb = argv[i]
		case "-inet":
		case "-inet6":
			v6 = true
		case "default":
			if v6 {
				r.dst = netip.MustParsePrefix("::/0")
			} else {
				r.dst = netip.MustParsePrefix("0.0.0.0/0")
			}
		case "-net":
		case "-interface":
			if i+1 < len(argv) {
				r.iface, i = argv[i+1], i+1
			}
		case "-ifscope":
			if i+1 < len(argv) {
				r.iface, r.scoped, i = argv[i+1], true, i+1
			}
		default:
			if p, err := netip.ParsePrefix(argv[i]); err == nil {
				r.dst = p
			} else if a, err := netip.ParseAddr(argv[i]); err == nil {
				r.gw = a
			}
		}
	}
	return r, r.verb != "" && r.dst.IsValid()
}

func openTempJournal(t *testing.T) netstate.Journal {
	t.Helper()
	j, err := netstate.OpenJournal(t.TempDir() + "/journal.ndjson")
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}
