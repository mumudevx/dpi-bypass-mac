package netstate

import (
	"net/netip"
	"os"
	"testing"
)

// TestLiveRIBReadableUnprivileged is the acceptance criterion for the AF_ROUTE
// reader: it must work as an ordinary user, because the proxy front-end runs
// without sudo and still has to verify what it did to the routing table.
func TestLiveRIBReadableUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test is only meaningful as a non-root uid")
	}
	rib := NewRIB()
	routes, err := rib.Routes()
	if err != nil {
		t.Fatalf("Routes() as uid %d: %v", os.Getuid(), err)
	}
	if len(routes) == 0 {
		t.Fatal("the live routing table came back empty")
	}
	t.Logf("read %d routes from the live RIB as uid %d", len(routes), os.Getuid())

	sawV4, sawIface := false, false
	for _, r := range routes {
		if !r.Dst.IsValid() {
			t.Fatalf("route with an invalid destination: %+v", r)
		}
		if r.Dst.Addr().Is4() {
			sawV4 = true
		}
		if r.Iface != "" {
			sawIface = true
		}
	}
	if !sawV4 {
		t.Fatal("no IPv4 routes were parsed")
	}
	if !sawIface {
		t.Fatal("no route was attributed to an interface")
	}

	// Loopback is present on every macOS machine and is the one route we can
	// assert on without knowing anything about this network.
	if ok, err := rib.Exists(netip.MustParsePrefix("127.0.0.0/8"), "lo0"); err != nil || !ok {
		t.Fatalf("Exists(127.0.0.0/8, lo0) = %v, %v", ok, err)
	}
	if ok, _ := rib.Exists(netip.MustParsePrefix("203.0.113.0/24"), "en0"); ok {
		t.Fatal("Exists reported a route to a TEST-NET-3 prefix")
	}

	if def, ok, err := rib.Default(); err != nil {
		t.Fatalf("Default(): %v", err)
	} else if ok {
		if def.Dst.Bits() != 0 {
			t.Fatalf("Default() returned %s, which is not a default route", def.Dst)
		}
		if def.Scoped {
			t.Fatalf("Default() returned a scoped route: %s", def)
		}
		t.Logf("default route: %s", def)
	}

	// ScopedDefault must not return the unscoped default under any name.
	if e, ok, err := rib.ScopedDefault("lo0"); err != nil {
		t.Fatalf("ScopedDefault: %v", err)
	} else if ok && !e.Scoped {
		t.Fatalf("ScopedDefault returned an unscoped route: %s", e)
	}
}

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
