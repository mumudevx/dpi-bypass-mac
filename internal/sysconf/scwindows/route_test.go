//go:build windows

package scwindows

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// These tests can only run on a Windows host, and CI does not yet have one; see
// iphlp_test.go. GOOS=windows go vet compiles them and nothing more. They exist
// anyway because the mapping they pin is the one thing in this package that
// cannot be checked by reading: a wrong field does not fail to compile, it
// writes a wrong row into a real machine's routing table.

// The expectation helpers below build SOCKADDR_INET byte by byte from the C
// layout, NOT by calling setSockaddr. That is the whole point: an offset error
// in the code under test must not be mirrored in the value it is compared
// against.
//
// windows.RawSockaddrInet is { Family uint16; Port uint16; Data [6]uint32 }, so
// Data[0] begins at offset 4, Data[1] at 8, ... Data[5] at 24. Windows runs
// only on little-endian architectures, so storing the four address bytes
// through binary.LittleEndian.Uint32 lays byte 0 at the lowest offset — network
// order, which is what IN_ADDR and IN6_ADDR hold.

// sockaddrIn builds a SOCKADDR_INET holding an IPv4 address.
//
// SOCKADDR_IN (ws2def.h):
//
//	0  USHORT  sin_family
//	2  USHORT  sin_port
//	4  IN_ADDR sin_addr   (4 bytes)   -> Data[0]
//	8  CHAR    sin_zero[8]            -> Data[1], Data[2]
func sockaddrIn(t *testing.T, a string) windows.RawSockaddrInet {
	t.Helper()
	ip, err := netip.ParseAddr(a)
	if err != nil || !ip.Is4() {
		t.Fatalf("sockaddrIn: %q is not an IPv4 address (%v)", a, err)
	}
	b := ip.As4()
	var sa windows.RawSockaddrInet
	sa.Family = 2 // AF_INET, ws2def.h
	sa.Data[0] = binary.LittleEndian.Uint32(b[:])
	return sa
}

// sockaddrIn6 builds a SOCKADDR_INET holding an IPv6 address.
//
// SOCKADDR_IN6 (ws2ipdef.h):
//
//	 0  USHORT   sin6_family
//	 2  USHORT   sin6_port
//	 4  ULONG    sin6_flowinfo        -> Data[0]
//	 8  IN6_ADDR sin6_addr (16 bytes) -> Data[1..4]
//	24  ULONG    sin6_scope_id        -> Data[5]
func sockaddrIn6(t *testing.T, a string, scopeID uint32) windows.RawSockaddrInet {
	t.Helper()
	ip, err := netip.ParseAddr(a)
	if err != nil || ip.Is4() {
		t.Fatalf("sockaddrIn6: %q is not an IPv6 address (%v)", a, err)
	}
	b := ip.As16()
	var sa windows.RawSockaddrInet
	sa.Family = 23 // AF_INET6, ws2def.h
	for i := 0; i < 4; i++ {
		sa.Data[1+i] = binary.LittleEndian.Uint32(b[i*4 : i*4+4])
	}
	sa.Data[5] = scopeID
	return sa
}

// TestRouteRowMapsEverySpecShape pins RouteSpec -> MIB_IPFORWARD_ROW2 field for
// field. Whole-struct comparison is deliberate: a field nobody thought to
// assert is exactly the field that ends up wrong, and MIB_IPFORWARD_ROW2 is
// comparable, so there is no excuse for asserting a subset.
func TestRouteRowMapsEverySpecShape(t *testing.T) {
	const ifIndex = 17

	base := func() windows.MibIpForwardRow2 {
		return windows.MibIpForwardRow2{
			InterfaceLuid:     0, // unset on purpose: MSDN uses LUID first, index only when LUID is zero
			InterfaceIndex:    ifIndex,
			SitePrefixLength:  0,
			ValidLifetime:     0xffffffff,
			PreferredLifetime: 0xffffffff,
			Metric:            0,
			Protocol:          3, // MIB_IPPROTO_NETMGMT, nldef.h
		}
	}

	v4Default := func() windows.MibIpForwardRow2 {
		r := base()
		r.DestinationPrefix.Prefix = sockaddrIn(t, "0.0.0.0")
		r.DestinationPrefix.PrefixLength = 0
		return r
	}

	cases := []struct {
		name string
		spec sysport.RouteSpec
		want windows.MibIpForwardRow2
	}{
		{
			// Shape 1: the scoped uplink default tunfe installs before the
			// datapath starts.
			name: "scoped gateway route v4",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("0.0.0.0/0"),
				Gw:    netip.MustParseAddr("192.168.1.1"),
				Iface: "Wi-Fi",
			},
			want: func() windows.MibIpForwardRow2 {
				r := v4Default()
				r.NextHop = sockaddrIn(t, "192.168.1.1")
				return r
			}(),
		},
		{
			// Shape 3: a capture route. NextHop is all zeros but CARRIES THE
			// FAMILY; a left-zeroed SOCKADDR_INET would be AF_UNSPEC and
			// CreateIpForwardEntry2 rejects it with ERROR_INVALID_PARAMETER.
			name: "interface route v4 nexthop is unspecified but typed",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("0.0.0.0/1"),
				Iface: "dpb0",
			},
			want: func() windows.MibIpForwardRow2 {
				r := base()
				r.DestinationPrefix.Prefix = sockaddrIn(t, "0.0.0.0")
				r.DestinationPrefix.PrefixLength = 1
				r.NextHop = sockaddrIn(t, "0.0.0.0")
				return r
			}(),
		},
		{
			name: "interface route v4 upper half",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("128.0.0.0/1"),
				Iface: "dpb0",
			},
			want: func() windows.MibIpForwardRow2 {
				r := base()
				r.DestinationPrefix.Prefix = sockaddrIn(t, "128.0.0.0")
				r.DestinationPrefix.PrefixLength = 1
				r.NextHop = sockaddrIn(t, "0.0.0.0")
				return r
			}(),
		},
		{
			name: "host route for a nameserver",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("8.8.8.8/32"),
				Iface: "dpb0",
			},
			want: func() windows.MibIpForwardRow2 {
				r := base()
				r.DestinationPrefix.Prefix = sockaddrIn(t, "8.8.8.8")
				r.DestinationPrefix.PrefixLength = 32
				r.NextHop = sockaddrIn(t, "0.0.0.0")
				return r
			}(),
		},
		{
			name: "scoped gateway route v6",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("::/0"),
				Gw:    netip.MustParseAddr("2001:db8::1"),
				Iface: "Ethernet",
			},
			want: func() windows.MibIpForwardRow2 {
				r := base()
				r.DestinationPrefix.Prefix = sockaddrIn6(t, "::", 0)
				r.DestinationPrefix.PrefixLength = 0
				// A global next hop is not scoped to an interface, so
				// sin6_scope_id stays zero.
				r.NextHop = sockaddrIn6(t, "2001:db8::1", 0)
				return r
			}(),
		},
		{
			// A link-local next hop is meaningless without its interface, and
			// the only interface that can be meant is the one the route is
			// being installed on.
			name: "link-local v6 next hop takes the interface index as scope id",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("::/0"),
				Gw:    netip.MustParseAddr("fe80::1"),
				Iface: "Ethernet",
			},
			want: func() windows.MibIpForwardRow2 {
				r := base()
				r.DestinationPrefix.Prefix = sockaddrIn6(t, "::", 0)
				r.DestinationPrefix.PrefixLength = 0
				r.NextHop = sockaddrIn6(t, "fe80::1", ifIndex)
				return r
			}(),
		},
		{
			// scdarwin's RIB reader attaches an interface NAME as the zone.
			// sin6_scope_id is a numeric index, so the name is dropped and the
			// index used; the row must not differ from the unzoned case.
			name: "a zone on the spec gateway does not change the row",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("::/0"),
				Gw:    netip.MustParseAddr("fe80::1%Ethernet"),
				Iface: "Ethernet",
			},
			want: func() windows.MibIpForwardRow2 {
				r := base()
				r.DestinationPrefix.Prefix = sockaddrIn6(t, "::", 0)
				r.DestinationPrefix.PrefixLength = 0
				r.NextHop = sockaddrIn6(t, "fe80::1", ifIndex)
				return r
			}(),
		},
		{
			name: "interface route v6 nexthop is unspecified but typed",
			spec: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("8000::/1"),
				Iface: "dpb0",
			},
			want: func() windows.MibIpForwardRow2 {
				r := base()
				r.DestinationPrefix.Prefix = sockaddrIn6(t, "8000::", 0)
				r.DestinationPrefix.PrefixLength = 1
				r.NextHop = sockaddrIn6(t, "::", 0)
				return r
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := routeRow(tc.spec, ifIndex)
			if err != nil {
				t.Fatalf("routeRow(%+v): %v", tc.spec, err)
			}
			if *got != tc.want {
				t.Errorf("routeRow(%+v) mismatch\n got %+v\nwant %+v", tc.spec, *got, tc.want)
			}
		})
	}
}

// TestRouteRowNextHopAlwaysCarriesAFamily states the interface-route rule on
// its own, because it is the one that a plausible implementation gets wrong and
// that no compiler catches. MSDN requires NextHop be "initialized to a valid
// IPv4 or IPv6 address and family"; a zero SOCKADDR_INET is AF_UNSPEC and
// CreateIpForwardEntry2 answers ERROR_INVALID_PARAMETER.
func TestRouteRowNextHopAlwaysCarriesAFamily(t *testing.T) {
	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		row, err := routeRow(sysport.RouteSpec{Dst: netip.MustParsePrefix(dst), Iface: "dpb0"}, 9)
		if err != nil {
			t.Fatalf("routeRow(%s): %v", dst, err)
		}
		if row.NextHop.Family == 0 {
			t.Errorf("routeRow(%s): NextHop.Family is AF_UNSPEC; CreateIpForwardEntry2 rejects that", dst)
		}
		if row.NextHop.Family != row.DestinationPrefix.Prefix.Family {
			t.Errorf("routeRow(%s): NextHop family %d != destination family %d",
				dst, row.NextHop.Family, row.DestinationPrefix.Prefix.Family)
		}
		gw, ok := sockaddrAddr(&row.NextHop)
		if !ok || !gw.IsUnspecified() {
			t.Errorf("routeRow(%s): NextHop should be the all-zeros address, got %v (ok=%v)", dst, gw, ok)
		}
	}
}

// TestRouteRowRefusesAPlainGatewayRoute pins the decision documented on
// errRouteNeedsIface: RouteSpec's second shape has no Windows row that could
// ever verify, so it is refused before anything is written.
func TestRouteRowRefusesAPlainGatewayRoute(t *testing.T) {
	_, err := routeRow(sysport.RouteSpec{
		Dst: netip.MustParsePrefix("10.0.0.0/8"),
		Gw:  netip.MustParseAddr("192.168.1.1"),
	}, 4)
	if !errors.Is(err, errRouteNeedsIface) {
		t.Fatalf("routeRow with no Iface: got %v, want errRouteNeedsIface", err)
	}
}

// TestRouteRowRefusesAFamilyMismatch keeps a v4 destination from being given a
// v6 next hop. SOCKADDR_INET is a union: writing the wrong arm produces a row
// that is structurally valid and semantically nonsense.
func TestRouteRowRefusesAFamilyMismatch(t *testing.T) {
	cases := []sysport.RouteSpec{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gw: netip.MustParseAddr("fe80::1"), Iface: "Ethernet"},
		{Dst: netip.MustParsePrefix("::/0"), Gw: netip.MustParseAddr("192.168.1.1"), Iface: "Ethernet"},
	}
	for _, s := range cases {
		if _, err := routeRow(s, 3); err == nil {
			t.Errorf("routeRow(%+v): accepted a next hop of the wrong family", s)
		}
	}
}

// TestRouteRowMasksTheDestination: the forwarding table stores masked prefixes,
// so a row carrying host bits below PrefixLength would never read back as the
// prefix that was asked for, and Verify would fail forever.
func TestRouteRowMasksTheDestination(t *testing.T) {
	row, err := routeRow(sysport.RouteSpec{
		Dst:   netip.MustParsePrefix("10.1.2.3/8"),
		Iface: "dpb0",
	}, 6)
	if err != nil {
		t.Fatalf("routeRow: %v", err)
	}
	got, ok := sockaddrAddr(&row.DestinationPrefix.Prefix)
	if !ok {
		t.Fatal("routeRow: destination prefix has no readable family")
	}
	if want := netip.MustParseAddr("10.0.0.0"); got != want {
		t.Errorf("destination = %v, want %v (masked)", got, want)
	}
}

// TestRouteRowRefusesA4in6Destination: ::ffff:10.0.0.0/104 IS 10.0.0.0/8, and
// netip does not rebase the length when the address is unmapped. An
// implementation that calls Unmap() and keeps Bits() writes PrefixLength 104
// into an AF_INET row — valid Go, valid struct, nonsense route. Refusing is the
// only answer that cannot be silently wrong.
func TestRouteRowRefusesA4in6Destination(t *testing.T) {
	if _, err := routeRow(sysport.RouteSpec{
		Dst:   netip.MustParsePrefix("::ffff:10.0.0.0/104"),
		Iface: "dpb0",
	}, 6); err == nil {
		t.Fatal("routeRow accepted an IPv4-mapped IPv6 destination prefix")
	}
}

// TestRouteRowConstantsMatchTheMSDNContract restates the three constants as
// assertions about CreateIpForwardEntry2's documented ERROR_INVALID_PARAMETER
// conditions, so that changing one has to argue with the contract.
func TestRouteRowConstantsMatchTheMSDNContract(t *testing.T) {
	row, err := routeRow(sysport.RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/0"), Iface: "dpb0"}, 1)
	if err != nil {
		t.Fatalf("routeRow: %v", err)
	}
	// "if the SitePrefixLength ... is greater than the prefix length specified
	// in the DestinationPrefix" — a default route's prefix length is 0, so only
	// 0 is legal here.
	if row.SitePrefixLength > row.DestinationPrefix.PrefixLength {
		t.Errorf("SitePrefixLength %d > PrefixLength %d; CreateIpForwardEntry2 rejects that",
			row.SitePrefixLength, row.DestinationPrefix.PrefixLength)
	}
	// "if the PreferredLifetime member ... is greater than the ValidLifetime
	// member".
	if row.PreferredLifetime > row.ValidLifetime {
		t.Errorf("PreferredLifetime %d > ValidLifetime %d; CreateIpForwardEntry2 rejects that",
			row.PreferredLifetime, row.ValidLifetime)
	}
	// Both infinite, so the route does not expire mid-session.
	if row.ValidLifetime != 0xffffffff {
		t.Errorf("ValidLifetime = %#x, want 0xffffffff (MSDN: infinite)", row.ValidLifetime)
	}
	// "both the InterfaceLuid or InterfaceIndex members ... were unspecified"
	// is an error; the index is what carries the interface here.
	if row.InterfaceIndex == 0 {
		t.Error("InterfaceIndex is 0 and InterfaceLuid is unset; the row names no interface")
	}
	// Age and Origin are set by the stack and ignored on input; leaving them
	// non-zero would be claiming something the call does not honour.
	if row.Age != 0 || row.Origin != 0 {
		t.Errorf("Age=%d Origin=%d; MSDN says both are ignored on input", row.Age, row.Origin)
	}
}

// TestIfaceIndexRefusesTheEmptyName guards the path that would otherwise hand
// CreateIpForwardEntry2 index 0, which it reads as "unspecified".
func TestIfaceIndexRefusesTheEmptyName(t *testing.T) {
	if _, err := ifaceIndex(""); !errors.Is(err, errRouteNeedsIface) {
		t.Fatalf("ifaceIndex(\"\"): got %v, want errRouteNeedsIface", err)
	}
}
