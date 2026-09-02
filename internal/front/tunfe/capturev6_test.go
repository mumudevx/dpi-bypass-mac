package tunfe

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// IPv6 capture, and the gate that makes its absence safe.
//
// DOSSIER GT19: the IPv6 sinkhole 2a01:358:4014:a00::3 is registered in RIPE to
// BTK itself, so AAAA poisoning is half the block on this line. A tunnel that
// captures only IPv4 while the resolver keeps answering AAAA hands applications
// addresses for traffic it cannot protect — which is the worst category of
// defect for a censorship tool, because everything looks like it is working.
// Either the v6 halves are installed AND verified, or IPv6Gate stays closed and
// resolve suppresses AAAA. There is no third state.

func testCaptureV6(gate *IPv6Gate) Capture {
	c := testCapture()
	c.LocalV6 = netip.MustParseAddr("fd6b:1dea::1")
	c.GatewayV6 = netip.MustParseAddr("fe80::1")
	c.V6Gate = gate
	return c
}

// TestBringUpOrderingWithIPv6 extends docs/PLAN.md data path F to the second
// family. The rules are the same and for the same reasons: the address before
// any route that names the device, the scoped default before the capture routes
// so our own upstream sockets keep an escape, and the datapath listening before
// either half of the address space points at it.
func TestBringUpOrderingWithIPv6(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	gate := &IPv6Gate{}
	started := -1

	err := testCaptureV6(gate).BringUp(context.Background(), seq, func(context.Context) error {
		started = len(seq.ids())
		return nil
	})
	if err != nil {
		t.Fatalf("BringUp: %v", err)
	}

	want := []string{
		"ifconfig:utun7/10.6.6.1",
		"ifconfig:utun7/fd6b:1dea::1",
		"route:0.0.0.0/0@en0",
		"route:::/0@en0",
		"route:0.0.0.0/1@utun7",
		"route:128.0.0.0/1@utun7",
		"route:::/1@utun7",
		"route:8000::/1@utun7",
		"route:192.168.1.1/32@utun7",
		"dns.servers:Wi-Fi",
	}
	got := seq.ids()
	if len(got) != len(want) {
		t.Fatalf("applied %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d = %q, want %q (full order %v)", i, got[i], want[i], got)
		}
	}
	if started != 4 {
		t.Fatalf("the datapath started after %d Op(s), want 4: both scoped defaults must exist "+
			"before either capture half, and nothing may point at the tunnel before it listens", started)
	}
	if !gate.Captured() {
		t.Fatal("the gate is closed after a complete bring-up, so AAAA would be suppressed on a tunnel that is carrying IPv6")
	}
}

// TestIPv6GateStaysClosedWhenACaptureRouteFails is the fail-closed half. A
// half-installed capture is the dangerous state: ::/1 is ours and 8000::/1 is
// not, so half of IPv6 leaves the machine unprotected. The gate must not open,
// and AAAA must therefore stay suppressed.
func TestIPv6GateStaysClosedWhenACaptureRouteFails(t *testing.T) {
	t.Parallel()
	// Step 7 is the second IPv6 capture half; every step before it succeeded.
	seq := &recordingSequencer{failAt: 7, failErr: errors.New("route: writing to routing socket")}
	gate := &IPv6Gate{}
	gate.Set(true) // a stale open gate from a previous network must not survive

	err := testCaptureV6(gate).BringUp(context.Background(), seq, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("BringUp reported success after a capture route failed")
	}
	if gate.Captured() {
		t.Fatal("the gate is open after a failed IPv6 capture: applications would be handed AAAA records " +
			"for traffic half of which escapes the tunnel")
	}
}

// TestNoIPv6AddressMeansNoIPv6Capture: without a tunnel address there is
// nothing to route v6 to, so nothing v6 is installed at all — and the gate,
// which defaults closed, is what keeps that honest at the resolver.
func TestNoIPv6AddressMeansNoIPv6Capture(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	gate := &IPv6Gate{}
	c := testCapture()
	c.V6Gate = gate

	if err := c.BringUp(context.Background(), seq, nil); err != nil {
		t.Fatalf("BringUp: %v", err)
	}
	for _, id := range seq.ids() {
		if id == "route:::/1@utun7" || id == "route:8000::/1@utun7" {
			t.Fatalf("IPv6 was captured with no IPv6 address on the device: %v", seq.ids())
		}
	}
	if gate.Captured() {
		t.Fatal("the gate opened for a v4-only tunnel")
	}
}

// TestTearDownClosesTheIPv6Gate: the gate must shut BEFORE the first route is
// deleted. Between the first `route delete` and the last, IPv6 is no longer
// captured, and anything this process answers in that window would be an
// address nothing is protecting.
func TestTearDownClosesTheIPv6Gate(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	gate := &IPv6Gate{}
	c := testCaptureV6(gate)
	if err := c.BringUp(context.Background(), seq, nil); err != nil {
		t.Fatalf("BringUp: %v", err)
	}
	if !gate.Captured() {
		t.Fatal("the gate never opened")
	}

	openAtUndo := true
	seq.onUndo = func() { openAtUndo = gate.Captured() }
	link, _ := NewPipe(0)
	if errs := c.TearDown(context.Background(), seq, nil, link); len(errs) != 0 {
		t.Fatalf("TearDown: %v", errs)
	}
	if openAtUndo {
		t.Fatal("the gate was still open while the routes were being deleted")
	}
	if gate.Captured() {
		t.Fatal("the gate is open after teardown")
	}
}

// TestNilIPv6GateIsClosed: a caller that forgot to wire a gate must get the
// safe answer, not a nil dereference and not an assumption of protection.
func TestNilIPv6GateIsClosed(t *testing.T) {
	t.Parallel()
	var g *IPv6Gate
	if g.Captured() {
		t.Fatal("a nil gate claims IPv6 is protected")
	}
	g.Set(true) // must not panic
	if g.Captured() {
		t.Fatal("a nil gate can be opened")
	}
	if (&IPv6Gate{}).Captured() {
		t.Fatal("the zero gate is open")
	}
}

// TestCaptureRoutesV6AreTheTwoHalves: the halves are used rather than ::/0 for
// the same reason as in IPv4 — the machine's own default route survives
// underneath, so our upstream sockets escape by binding to the uplink and the
// tunnel can be torn down without the machine losing its gateway.
func TestCaptureRoutesV6AreTheTwoHalves(t *testing.T) {
	t.Parallel()
	got := CaptureRoutesV6()
	want := []string{"::/1", "8000::/1"}
	if len(got) != len(want) {
		t.Fatalf("CaptureRoutesV6 = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("CaptureRoutesV6 = %v, want %v", got, want)
		}
	}
}

// TestCustomIPv6CaptureRoutesAreUsed keeps the field live: a caller that names
// its own prefixes must get them, not the default pair.
func TestCustomIPv6CaptureRoutesAreUsed(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	gate := &IPv6Gate{}
	c := testCaptureV6(gate)
	c.RoutesV6 = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	if err := c.BringUp(context.Background(), seq, nil); err != nil {
		t.Fatalf("BringUp: %v", err)
	}
	found := false
	for _, id := range seq.ids() {
		if id == "route:2001:db8::/32@utun7" {
			found = true
		}
		if id == "route:::/1@utun7" {
			t.Fatalf("the default pair was installed alongside a custom prefix: %v", seq.ids())
		}
	}
	if !found {
		t.Fatalf("the custom prefix was not installed: %v", seq.ids())
	}
}

// TestEmptyIPv6RouteSetIsRefused: an address on the device is not a capture. A
// caller that asks for one with no routes gets an error and a closed gate,
// because opening on an address alone would serve AAAA for traffic that leaves
// by the machine's own default route.
func TestEmptyIPv6RouteSetIsRefused(t *testing.T) {
	t.Parallel()
	gate := &IPv6Gate{}
	c := testCaptureV6(gate)
	c.RoutesV6 = []netip.Prefix{}
	err := c.BringUp(context.Background(), &recordingSequencer{}, nil)
	if err == nil {
		t.Fatal("BringUp accepted an IPv6 address with no capture routes")
	}
	if gate.Captured() {
		t.Fatal("the gate opened with no IPv6 capture routes installed")
	}
}
