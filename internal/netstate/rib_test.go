package netstate

import (
	"net/netip"
	"testing"
)

// TestLiveRIBReadableUnprivileged moved to rib_darwin_test.go; see the
// build-tag comment there for the two BSD facts it asserts — the `lo0`/`en0`
// interface names and a POSIX uid — and rib_windows_test.go for the same
// acceptance criterion asserted against the IP Helper reader.

// TestMatchRoute is the matchRoute half of what was one function with
// routeExists. routeExists implements the RIB reader's Exists and moved with
// it; matchRoute decides whether an entry is the one THIS Op installed, scope
// flag included, which is netstate's rule and stayed. Every assertion on either
// side is the one it always was; scdarwin's half is TestRouteExists.
func TestMatchRoute(t *testing.T) {
	rs := []RouteEntry{
		{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "utun4"},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.0.1"), Iface: "en0", Scoped: true},
	}
	gw := netip.MustParseAddr("192.168.0.1")
	if !matchRoute(rs, netip.MustParsePrefix("0.0.0.0/0"), gw, "en0", true) {
		t.Fatal("matchRoute missed the scoped default")
	}
	// The load-bearing case: an -ifscope add that landed unscoped must not pass.
	unscoped := []RouteEntry{{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: gw, Iface: "en0"}}
	if matchRoute(unscoped, netip.MustParsePrefix("0.0.0.0/0"), gw, "en0", true) {
		t.Fatal("matchRoute accepted an unscoped route where a scoped one was required")
	}
	if matchRoute(rs, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("10.0.0.1"), "en0", true) {
		t.Fatal("matchRoute ignored the gateway")
	}
}

func TestSameGatewayIgnoresZone(t *testing.T) {
	a := netip.MustParseAddr("fe80::1").WithZone("utun0")
	b := netip.MustParseAddr("fe80::1")
	if !sameGateway(a, b) {
		t.Fatal("sameGateway must ignore the zone the kernel attaches")
	}
	if sameGateway(a, netip.MustParseAddr("fe80::2")) {
		t.Fatal("sameGateway matched different addresses")
	}
}

func TestRouteEntryString(t *testing.T) {
	e := RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "utun4", Index: 22}
	if got := e.String(); got != "0.0.0.0/1 via - dev utun4(22)" {
		t.Fatalf("String() = %q", got)
	}
	e.Gateway = netip.MustParseAddr("192.168.0.1")
	e.Scoped = true
	if got := e.String(); got != "0.0.0.0/1 via 192.168.0.1 dev utun4(22) scoped" {
		t.Fatalf("String() = %q", got)
	}
}
