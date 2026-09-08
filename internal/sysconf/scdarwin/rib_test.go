package scdarwin

import (
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

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

// TestRouteExists is the routeExists half of what was one function with
// matchRoute. The two ask different questions of the same table — routeExists
// answers "is anything here", matchRoute answers "is what I installed here,
// with the scope I asked for" — and only the first one moved with the RIB
// reader it implements. matchRoute's half stayed in netstate, assertions
// unchanged, as TestMatchRoute.
func TestRouteExists(t *testing.T) {
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
}
