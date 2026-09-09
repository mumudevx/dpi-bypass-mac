//go:build windows

package scwindows

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// These tests can only run on a Windows host; see iphlp_test.go. GOOS=windows
// go vet compiles them and nothing more.

// row builds a MIB_IPFORWARD_ROW2 the way the kernel would hand one back, using
// the byte-level SOCKADDR_INET helpers in route_test.go rather than
// setSockaddr, so the reader is checked against the C layout and not against
// the writer.
func row(t *testing.T, dst windows.RawSockaddrInet, bits uint8, nextHop windows.RawSockaddrInet, ifIndex uint32) windows.MibIpForwardRow2 {
	t.Helper()
	var r windows.MibIpForwardRow2
	r.InterfaceIndex = ifIndex
	r.DestinationPrefix.Prefix = dst
	r.DestinationPrefix.PrefixLength = bits
	r.NextHop = nextHop
	return r
}

func TestRouteEntryFromTranslatesRows(t *testing.T) {
	names := map[int]string{5: "Wi-Fi", 17: "dpb0"}

	cases := []struct {
		name string
		row  windows.MibIpForwardRow2
		want sysport.RouteEntry
	}{
		{
			// The machine's own default. It has a next hop, so under this
			// package's definition it is Scoped; see routeEntryFrom.
			name: "gateway default route reads as scoped",
			row:  row(t, sockaddrIn(t, "0.0.0.0"), 0, sockaddrIn(t, "192.168.1.1"), 5),
			want: sysport.RouteEntry{
				Dst:     netip.MustParsePrefix("0.0.0.0/0"),
				Gateway: netip.MustParseAddr("192.168.1.1"),
				Iface:   "Wi-Fi",
				Index:   5,
				Scoped:  true,
			},
		},
		{
			// A capture route: on-link, next hop all zeros. MSDN calls that
			// "unspecified", and it is not a Gateway to us.
			name: "on-link route reads as unscoped with no gateway",
			row:  row(t, sockaddrIn(t, "0.0.0.0"), 1, sockaddrIn(t, "0.0.0.0"), 17),
			want: sysport.RouteEntry{
				Dst:   netip.MustParsePrefix("0.0.0.0/1"),
				Iface: "dpb0",
				Index: 17,
			},
		},
		{
			name: "host route",
			row:  row(t, sockaddrIn(t, "8.8.8.8"), 32, sockaddrIn(t, "0.0.0.0"), 17),
			want: sysport.RouteEntry{
				Dst:   netip.MustParsePrefix("8.8.8.8/32"),
				Iface: "dpb0",
				Index: 17,
			},
		},
		{
			name: "v6 gateway default",
			row:  row(t, sockaddrIn6(t, "::", 0), 0, sockaddrIn6(t, "2001:db8::1", 0), 5),
			want: sysport.RouteEntry{
				Dst:     netip.MustParsePrefix("::/0"),
				Gateway: netip.MustParseAddr("2001:db8::1"),
				Iface:   "Wi-Fi",
				Index:   5,
				Scoped:  true,
			},
		},
		{
			// The zone makes fe80::1%Wi-Fi distinguishable from fe80::1%dpb0
			// when several tunnels each install a default; scdarwin attaches
			// the same one from the same source.
			name: "link-local v6 gateway carries the interface name as a zone",
			row:  row(t, sockaddrIn6(t, "::", 0), 0, sockaddrIn6(t, "fe80::1", 5), 5),
			want: sysport.RouteEntry{
				Dst:     netip.MustParsePrefix("::/0"),
				Gateway: netip.MustParseAddr("fe80::1").WithZone("Wi-Fi"),
				Iface:   "Wi-Fi",
				Index:   5,
				Scoped:  true,
			},
		},
		{
			// An interface the name cache has not seen yet (it appeared between
			// the refresh and this read) still yields a usable entry; only the
			// name is missing, and the zone falls back to the index.
			name: "unknown interface index keeps the index and numbers the zone",
			row:  row(t, sockaddrIn6(t, "::", 0), 0, sockaddrIn6(t, "fe80::1", 99), 99),
			want: sysport.RouteEntry{
				Dst:     netip.MustParsePrefix("::/0"),
				Gateway: netip.MustParseAddr("fe80::1").WithZone("99"),
				Index:   99,
				Scoped:  true,
			},
		},
		{
			// The forwarding table stores masked prefixes, but a row that
			// somehow carried host bits must not produce an entry that no
			// masked comparison in netstate could ever match.
			name: "destination is masked",
			row:  row(t, sockaddrIn(t, "10.1.2.3"), 8, sockaddrIn(t, "0.0.0.0"), 17),
			want: sysport.RouteEntry{
				Dst:   netip.MustParsePrefix("10.0.0.0/8"),
				Iface: "dpb0",
				Index: 17,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := routeEntryFrom(&tc.row, names)
			if !ok {
				t.Fatalf("routeEntryFrom(%+v): refused the row", tc.row)
			}
			if got != tc.want {
				t.Errorf("routeEntryFrom mismatch\n got %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestRouteEntryFromRefusesRowsItCannotExpress(t *testing.T) {
	names := map[int]string{}

	// AF_UNSPEC destination: not an address family we can turn into a prefix.
	var unspec windows.RawSockaddrInet
	if _, ok := routeEntryFrom(&windows.MibIpForwardRow2{DestinationPrefix: windows.IpAddressPrefix{Prefix: unspec}}, names); ok {
		t.Error("routeEntryFrom accepted a row with an AF_UNSPEC destination")
	}

	// PrefixLength wider than the family. MSDN calls 255 "commonly used to
	// represent an illegal value"; inventing a prefix length beats nothing at
	// all, so the row is dropped instead.
	bad := row(t, sockaddrIn(t, "10.0.0.0"), 255, sockaddrIn(t, "0.0.0.0"), 1)
	if _, ok := routeEntryFrom(&bad, names); ok {
		t.Error("routeEntryFrom accepted a row with PrefixLength 255 on an IPv4 destination")
	}
	bad33 := row(t, sockaddrIn(t, "10.0.0.0"), 33, sockaddrIn(t, "0.0.0.0"), 1)
	if _, ok := routeEntryFrom(&bad33, names); ok {
		t.Error("routeEntryFrom accepted a /33 IPv4 destination")
	}
}

// TestScopedAgreesBetweenWriterAndReader is the test this package's design
// stands or falls on.
//
// netstate.matchRoute (internal/netstate/op_route.go) computes
//
//	wantScoped := gw.IsValid() && iface != ""
//
// and refuses any RIB entry whose Scoped differs. So for every RouteSpec that
// routeCtl.Add accepts, the row it writes MUST read back through
// routeEntryFrom with Scoped equal to that expression — otherwise Apply
// succeeds, Verify fails, and dpb tears down a route it correctly installed.
//
// This walks a spec through routeRow and straight back through routeEntryFrom,
// which is the same round trip a real Add + Verify makes with the kernel in the
// middle, minus the kernel.
func TestScopedAgreesBetweenWriterAndReader(t *testing.T) {
	const ifIndex = 17
	names := map[int]string{ifIndex: "dpb0"}

	specs := []sysport.RouteSpec{
		// Shape 1: scoped gateway routes (the uplink defaults).
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gw: netip.MustParseAddr("192.168.1.1"), Iface: "dpb0"},
		{Dst: netip.MustParsePrefix("::/0"), Gw: netip.MustParseAddr("2001:db8::1"), Iface: "dpb0"},
		{Dst: netip.MustParsePrefix("::/0"), Gw: netip.MustParseAddr("fe80::1"), Iface: "dpb0"},
		// Shape 3: interface routes (the capture routes).
		{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "dpb0"},
		{Dst: netip.MustParsePrefix("128.0.0.0/1"), Iface: "dpb0"},
		{Dst: netip.MustParsePrefix("::/1"), Iface: "dpb0"},
		{Dst: netip.MustParsePrefix("8000::/1"), Iface: "dpb0"},
		{Dst: netip.MustParsePrefix("8.8.8.8/32"), Iface: "dpb0"},
	}

	for _, s := range specs {
		r, err := routeRow(s, ifIndex)
		if err != nil {
			t.Fatalf("routeRow(%+v): %v", s, err)
		}
		got, ok := routeEntryFrom(r, names)
		if !ok {
			t.Fatalf("routeEntryFrom refused the row routeRow(%+v) produced", s)
		}
		wantScoped := s.Gw.IsValid() && s.Iface != ""
		if got.Scoped != wantScoped {
			t.Errorf("%+v: round-tripped Scoped=%v, matchRoute wants %v; every Verify would fail",
				s, got.Scoped, wantScoped)
		}
		if got.Dst != s.Dst.Masked() {
			t.Errorf("%+v: round-tripped Dst=%v, want %v", s, got.Dst, s.Dst.Masked())
		}
		if got.Iface != s.Iface {
			t.Errorf("%+v: round-tripped Iface=%q, want %q", s, got.Iface, s.Iface)
		}
		// matchRoute compares gateways through sameGateway, which strips the
		// zone; the reader attaches one and the spec may not have had it.
		if s.Gw.IsValid() && got.Gateway.WithZone("").Unmap() != s.Gw.WithZone("").Unmap() {
			t.Errorf("%+v: round-tripped Gateway=%v, want %v", s, got.Gateway, s.Gw)
		}
		if !s.Gw.IsValid() && got.Gateway.IsValid() {
			t.Errorf("%+v: round-tripped a gateway (%v) for an interface route", s, got.Gateway)
		}
	}
}

// TestPickDefaultDoesNotFilterOnScoped pins the one place this reader departs
// from scdarwin's. Carrying macOS' `if r.Scoped { continue }` across would make
// Default() return nothing on a normal Windows machine, because every default
// route there has a next hop and therefore reads as Scoped.
func TestPickDefaultDoesNotFilterOnScoped(t *testing.T) {
	rs := []sysport.RouteEntry{
		{Dst: netip.MustParsePrefix("192.168.1.0/24"), Iface: "Wi-Fi", Index: 5},
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Iface: "Wi-Fi", Index: 5, Scoped: true},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "Wi-Fi", Index: 5, Scoped: true},
	}
	got, ok, err := pickDefault(rs, "", nil)
	if err != nil || !ok {
		t.Fatalf("pickDefault: ok=%v err=%v; the machine's default route was not found", ok, err)
	}
	// IPv4 wins: callers use this to identify THE uplink, and the v4 default is
	// the one that names the physical adapter.
	if got.Dst != netip.MustParsePrefix("0.0.0.0/0") {
		t.Errorf("pickDefault chose %v, want the IPv4 default", got.Dst)
	}
	if got.Iface != "Wi-Fi" {
		t.Errorf("pickDefault chose iface %q, want Wi-Fi", got.Iface)
	}
}

func TestPickDefaultFallsBackToV6(t *testing.T) {
	rs := []sysport.RouteEntry{
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Iface: "Wi-Fi", Scoped: true},
	}
	got, ok, err := pickDefault(rs, "", nil)
	if err != nil || !ok {
		t.Fatalf("pickDefault: ok=%v err=%v", ok, err)
	}
	if got.Dst != netip.MustParsePrefix("::/0") {
		t.Errorf("pickDefault chose %v, want ::/0", got.Dst)
	}
}

func TestPickDefaultOnAnInterface(t *testing.T) {
	rs := []sysport.RouteEntry{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "Wi-Fi", Scoped: true},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Iface: "Ethernet", Scoped: true},
	}
	got, ok, err := pickDefault(rs, "Ethernet", nil)
	if err != nil || !ok {
		t.Fatalf("pickDefault(Ethernet): ok=%v err=%v", ok, err)
	}
	if got.Gateway != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("pickDefault(Ethernet) chose gateway %v, want 10.0.0.1", got.Gateway)
	}
	if _, ok, _ := pickDefault(rs, "dpb0", nil); ok {
		t.Error("pickDefault found a default on an interface that has none")
	}
}

// TestPickDefaultRanksByInterfaceMetric is the docked-laptop case, which is
// routine on Windows and not reachable on macOS: Ethernet plugged in with
// Wi-Fi still associated leaves TWO default routes in the table, and MSDN says
// so explicitly for MIB_IPFORWARD_ROW2. Taking the first would name whichever
// adapter the table happened to list first — and everything follows the
// uplink, so the scoped default and the DNS override would both land on the
// NIC carrying no traffic while dpb reported Ready.
//
// The metric lookup is injected because GetIpInterfaceEntry cannot run here;
// the numbers are Windows' own automatic metrics for a gigabit Ethernet (25)
// and an 802.11 link (45).
func TestPickDefaultRanksByInterfaceMetric(t *testing.T) {
	const (
		wifiIndex     = 5
		ethernetIndex = 12
	)
	metrics := map[int]uint32{wifiIndex: 45, ethernetIndex: 25}
	ifMetric := func(_ uint16, index int) uint32 { return metrics[index] }

	// Wi-Fi first in the table, so a first-match reader gets it wrong.
	rs := []sysport.RouteEntry{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "Wi-Fi", Index: wifiIndex, Scoped: true},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Iface: "Ethernet", Index: ethernetIndex, Scoped: true},
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Iface: "Wi-Fi", Index: wifiIndex, Scoped: true},
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::2"), Iface: "Ethernet", Index: ethernetIndex, Scoped: true},
	}

	got, ok, err := pickDefault(rs, "", ifMetric)
	if err != nil || !ok {
		t.Fatalf("pickDefault: ok=%v err=%v", ok, err)
	}
	if got.Iface != "Ethernet" {
		t.Errorf("pickDefault chose %q, want the lower-metric Ethernet", got.Iface)
	}

	// The v6 half is ranked by the same lookup, through facts.go's own picker.
	v6, ok := pickDefaultV6(rs, ifMetric)
	if !ok {
		t.Fatal("pickDefaultV6 found no v6 default")
	}
	if v6.Iface != "Ethernet" {
		t.Errorf("pickDefaultV6 chose %q, want the lower-metric Ethernet", v6.Iface)
	}

	// A metric the IP Helper API cannot report must LOSE, not win: an
	// interface it will not describe is not one to prefer. Here Wi-Fi is the
	// only readable one, so it takes the default it would otherwise lose.
	onlyWiFi := func(_ uint16, index int) uint32 {
		if index == wifiIndex {
			return 45
		}
		return unreadableInterfaceMetric
	}
	got, ok, err = pickDefault(rs, "", onlyWiFi)
	if err != nil || !ok {
		t.Fatalf("pickDefault (unreadable Ethernet): ok=%v err=%v", ok, err)
	}
	if got.Iface != "Wi-Fi" {
		t.Errorf("pickDefault chose %q, want Wi-Fi; an unreadable interface metric must lose", got.Iface)
	}
}

func TestRouteExists(t *testing.T) {
	rs := []sysport.RouteEntry{
		{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "dpb0"},
	}
	if !routeExists(rs, netip.MustParsePrefix("0.0.0.0/1"), "dpb0") {
		t.Error("routeExists missed a route that is present on the named interface")
	}
	if !routeExists(rs, netip.MustParsePrefix("0.0.0.0/1"), "") {
		t.Error("routeExists with no interface should match any interface")
	}
	// An unmasked query must still match: netstate hands prefixes around
	// already masked, but a caller that does not is asking the same question.
	if !routeExists(rs, netip.MustParsePrefix("0.1.2.3/1"), "dpb0") {
		t.Error("routeExists did not mask the query prefix")
	}
	if routeExists(rs, netip.MustParsePrefix("0.0.0.0/1"), "Wi-Fi") {
		t.Error("routeExists matched a route on the wrong interface")
	}
}

// TestIfaceNamesCachePropagatesTheReadFailure: a name map that could not be
// built is an error, never an empty map. An empty map would report every route
// with Iface "", and matchRoute would then reject every scoped comparison
// against a real interface name — a verification that fails for a reason
// nothing in the log explains.
func TestIfaceNamesCachePropagatesTheReadFailure(t *testing.T) {
	boom := errors.New("boom")
	prev := interfaceLister
	interfaceLister = func() ([]net.Interface, error) { return nil, boom }
	defer func() { interfaceLister = prev }()

	k := &kernelRIB{}
	if _, err := k.ifaceNames(); !errors.Is(err, boom) {
		t.Fatalf("ifaceNames: got %v, want the lister's error", err)
	}
}

func TestIfaceNamesCaches(t *testing.T) {
	calls := 0
	prev := interfaceLister
	interfaceLister = func() ([]net.Interface, error) {
		calls++
		return []net.Interface{{Index: 17, Name: "dpb0"}}, nil
	}
	defer func() { interfaceLister = prev }()

	k := &kernelRIB{}
	for i := 0; i < 3; i++ {
		m, err := k.ifaceNames()
		if err != nil {
			t.Fatalf("ifaceNames: %v", err)
		}
		if m[17] != "dpb0" {
			t.Fatalf("ifaceNames[17] = %q, want dpb0", m[17])
		}
	}
	if calls != 1 {
		t.Errorf("interfaceLister called %d times within the TTL, want 1", calls)
	}
}

// TestIfaceIndexResolvesThroughTheSameEnumeration: the writer and the reader
// must agree about which index a name means, so they go through one seam.
func TestIfaceIndexResolvesThroughTheSameEnumeration(t *testing.T) {
	prev := interfaceLister
	interfaceLister = func() ([]net.Interface, error) {
		return []net.Interface{{Index: 5, Name: "Wi-Fi"}, {Index: 17, Name: "dpb0"}}, nil
	}
	defer func() { interfaceLister = prev }()

	got, err := ifaceIndex("dpb0")
	if err != nil {
		t.Fatalf("ifaceIndex(dpb0): %v", err)
	}
	if got != 17 {
		t.Errorf("ifaceIndex(dpb0) = %d, want 17", got)
	}
	if _, err := ifaceIndex("nope"); err == nil {
		t.Error("ifaceIndex accepted an interface name that is not on the machine")
	}
}

func TestSockaddrAddrRejectsAnUnknownFamily(t *testing.T) {
	sa := windows.RawSockaddrInet{Family: 99}
	if _, ok := sockaddrAddr(&sa); ok {
		t.Error("sockaddrAddr decoded an address from an unknown family")
	}
}

func TestZoneNameFallsBackToTheIndex(t *testing.T) {
	if got := zoneName(5, map[int]string{5: "Wi-Fi"}); got != "Wi-Fi" {
		t.Errorf("zoneName = %q, want Wi-Fi", got)
	}
	if got := zoneName(99, map[int]string{}); got != "99" {
		t.Errorf("zoneName for an unknown index = %q, want \"99\"", got)
	}
}
