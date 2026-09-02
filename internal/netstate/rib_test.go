package netstate

import (
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
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

func TestRouteEntryFrom(t *testing.T) {
	names := map[int]string{14: "en0", 22: "utun4"}
	v4 := func(a, b, c, d byte) *route.Inet4Addr { return &route.Inet4Addr{IP: [4]byte{a, b, c, d}} }

	tests := []struct {
		name string
		msg  *route.RouteMessage
		want RouteEntry
		ok   bool
	}{
		{
			name: "gateway route",
			msg: &route.RouteMessage{
				Flags: unix.RTF_UP | unix.RTF_GATEWAY, Index: 14,
				Addrs: []route.Addr{v4(0, 0, 0, 0), v4(192, 168, 0, 1), v4(0, 0, 0, 0)},
			},
			want: RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.0.1"), Iface: "en0", Index: 14},
			ok:   true,
		},
		{
			name: "scoped route keeps the flag",
			msg: &route.RouteMessage{
				Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_IFSCOPE, Index: 14,
				Addrs: []route.Addr{v4(0, 0, 0, 0), v4(192, 168, 0, 1), v4(0, 0, 0, 0)},
			},
			want: RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.0.1"), Iface: "en0", Index: 14, Scoped: true},
			ok:   true,
		},
		{
			name: "host route ignores the netmask",
			msg: &route.RouteMessage{
				Flags: unix.RTF_UP | unix.RTF_HOST, Index: 14,
				Addrs: []route.Addr{v4(1, 1, 1, 1), v4(192, 168, 0, 1)},
			},
			want: RouteEntry{Dst: netip.MustParsePrefix("1.1.1.1/32"), Gateway: netip.MustParseAddr("192.168.0.1"), Iface: "en0", Index: 14},
			ok:   true,
		},
		{
			name: "interface route has no gateway",
			msg: &route.RouteMessage{
				Flags: unix.RTF_UP, Index: 22,
				Addrs: []route.Addr{v4(0, 0, 0, 0), &route.LinkAddr{Index: 22, Name: "utun4"}, v4(128, 0, 0, 0)},
			},
			want: RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "utun4", Index: 22},
			ok:   true,
		},
		{
			name: "down route is dropped",
			msg: &route.RouteMessage{
				Flags: 0, Index: 14,
				Addrs: []route.Addr{v4(0, 0, 0, 0), v4(192, 168, 0, 1)},
			},
		},
		{
			name: "message with no gateway slot is dropped",
			msg:  &route.RouteMessage{Flags: unix.RTF_UP, Index: 14, Addrs: []route.Addr{v4(1, 2, 3, 4)}},
		},
		{
			name: "unparseable destination is dropped",
			msg: &route.RouteMessage{
				Flags: unix.RTF_UP, Index: 14,
				Addrs: []route.Addr{&route.LinkAddr{Index: 14, Name: "en0"}, v4(192, 168, 0, 1)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := routeEntryFrom(tt.msg, names)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tt.ok, got)
			}
			if !ok {
				return
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMaskBits(t *testing.T) {
	cases := []struct {
		mask route.Addr
		want int
		ok   bool
		bits int
	}{
		{&route.Inet4Addr{IP: [4]byte{255, 255, 255, 255}}, 32, true, 32},
		{&route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}, 24, true, 32},
		{&route.Inet4Addr{IP: [4]byte{128, 0, 0, 0}}, 1, true, 32},
		{&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}}, 0, true, 32},
		{&route.Inet6Addr{}, 0, true, 128},
		// A family mismatch is a message we do not understand; refusing beats
		// inventing a prefix length.
		{&route.Inet4Addr{IP: [4]byte{255, 0, 0, 0}}, 0, false, 128},
		{&route.LinkAddr{}, 0, false, 32},
	}
	for _, c := range cases {
		got, ok := maskBits(c.mask, c.bits)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("maskBits(%v, %d) = %d, %v; want %d, %v", c.mask, c.bits, got, ok, c.want, c.ok)
		}
	}
}

func TestPickDefaultPrefersV4AndRespectsScope(t *testing.T) {
	v6def := RouteEntry{Dst: netip.MustParsePrefix("::/0"), Iface: "utun0", Scoped: true}
	v4def := RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Iface: "en0"}
	rs := []RouteEntry{
		{Dst: netip.MustParsePrefix("127.0.0.0/8"), Iface: "lo0"},
		v6def,
		v4def,
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Iface: "en0", Scoped: true},
	}
	got, ok, _ := pickDefault(rs, "")
	if !ok || got != v4def {
		t.Fatalf("pickDefault(unscoped) = %+v, %v", got, ok)
	}
	got, ok, _ = pickDefault(rs, "utun0")
	if !ok || got != v6def {
		t.Fatalf("pickDefault(utun0) = %+v, %v", got, ok)
	}
	if _, ok, _ := pickDefault(rs, "utun9"); ok {
		t.Fatal("pickDefault found a scoped default on an interface that has none")
	}
	if _, ok, _ := pickDefault(nil, ""); ok {
		t.Fatal("pickDefault found a default in an empty table")
	}
	// With only a v6 default present, fall back to it rather than reporting none.
	onlyV6 := []RouteEntry{{Dst: netip.MustParsePrefix("::/0"), Iface: "en0"}}
	if got, ok, _ := pickDefault(onlyV6, ""); !ok || got.Dst.Addr().Is4() {
		t.Fatalf("pickDefault(v6 only) = %+v, %v", got, ok)
	}
}

func TestRouteExistsAndMatchRoute(t *testing.T) {
	rs := []RouteEntry{
		{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "utun4"},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.0.1"), Iface: "en0", Scoped: true},
	}
	if !routeExists(rs, netip.MustParsePrefix("0.0.0.0/1"), "") {
		t.Fatal("routeExists missed a route when no interface was named")
	}
	if routeExists(rs, netip.MustParsePrefix("0.0.0.0/1"), "en0") {
		t.Fatal("routeExists matched the wrong interface")
	}
	// A destination given unmasked must still match.
	if !routeExists(rs, netip.MustParsePrefix("0.0.0.1/1"), "utun4") {
		t.Fatal("routeExists did not mask the destination before comparing")
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
