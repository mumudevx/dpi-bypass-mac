//go:build windows

package scwindows

import (
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// Everything tested here is pure: it takes routing-table entries or an already
// populated IP_ADAPTER_ADDRESSES and returns a value. factsCtl.Collect itself
// cannot be tested without a Windows host — it reads the real adapter list —
// which is why every decision it makes lives in one of these functions rather
// than inline.

func TestUplinkServicesIsTheUplinkAdapterNames(t *testing.T) {
	tests := []struct {
		name             string
		uplink, uplinkV6 string
		want             []string
	}{
		{"single-stack", "Wi-Fi", "", []string{"Wi-Fi"}},
		{"dual-stack on one adapter", "Wi-Fi", "Wi-Fi", []string{"Wi-Fi"}},
		{"v6 on another adapter", "Ethernet", "Wi-Fi", []string{"Ethernet", "Wi-Fi"}},
		{"v6 only", "", "Wi-Fi", []string{"Wi-Fi"}},
		{"no default route at all", "", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uplinkServices(tt.uplink, tt.uplinkV6)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("uplinkServices(%q, %q) = %v, want %v", tt.uplink, tt.uplinkV6, got, tt.want)
			}
		})
	}
}

func TestPickDefaultV6WantsAGateway(t *testing.T) {
	tests := []struct {
		name   string
		rs     []sysport.RouteEntry
		wantOK bool
		wantIf string
		wantGw string
	}{
		{
			name: "a v6 default with a next hop",
			rs: []sysport.RouteEntry{
				{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "Wi-Fi", Scoped: true},
				{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Iface: "Wi-Fi", Scoped: true},
			},
			wantOK: true, wantIf: "Wi-Fi", wantGw: "fe80::1",
		},
		{
			// The whole point of not carrying scdarwin's `!r.Scoped` filter
			// across: on Windows Scoped means "has a next hop", so the row we
			// want is always Scoped and the darwin filter would reject it.
			name: "a scoped row is the one we want, not the one we skip",
			rs: []sysport.RouteEntry{
				{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::abcd"), Iface: "Ethernet", Scoped: true},
			},
			wantOK: true, wantIf: "Ethernet", wantGw: "fe80::abcd",
		},
		{
			name: "an on-link v6 default is not a gateway route",
			rs: []sysport.RouteEntry{
				{Dst: netip.MustParsePrefix("::/0"), Iface: "dpb0"},
			},
		},
		{
			name: "a v4 default is not a v6 default",
			rs: []sysport.RouteEntry{
				{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "Wi-Fi", Scoped: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// nil ifMetric: these cases pin the FILTER, not the ranking, and a
			// nil lookup leaves first-seen order deciding — see routeMetric.
			// Ranking is pinned by rib_test.go's own metric cases.
			got, ok := pickDefaultV6(tt.rs, nil)
			if ok != tt.wantOK {
				t.Fatalf("pickDefaultV6 ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.Iface != tt.wantIf || got.Gateway.String() != tt.wantGw {
				t.Errorf("pickDefaultV6 = %s via %s, want %s via %s",
					got.Iface, got.Gateway, tt.wantIf, tt.wantGw)
			}
		})
	}
}

func TestClassifyVPN(t *testing.T) {
	v4def := func(iface, gw string) sysport.RouteEntry {
		return sysport.RouteEntry{
			Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr(gw),
			Iface: iface, Scoped: true,
		}
	}
	half := func(pfx, iface string, gw string) sysport.RouteEntry {
		e := sysport.RouteEntry{Dst: netip.MustParsePrefix(pfx), Iface: iface}
		if gw != "" {
			e.Gateway, e.Scoped = netip.MustParseAddr(gw), true
		}
		return e
	}

	tests := []struct {
		name             string
		rs               []sysport.RouteEntry
		uplink, uplinkV6 string
		selfIface        string
		want             sysport.VPNState
	}{
		{
			name:   "a plain single-homed machine has no VPN",
			rs:     []sysport.RouteEntry{v4def("Wi-Fi", "192.168.1.1")},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{},
		},
		{
			name: "the v6 uplink on another adapter is not a VPN",
			rs: []sysport.RouteEntry{
				v4def("Ethernet", "10.0.0.1"),
				{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Iface: "Wi-Fi", Scoped: true},
			},
			uplink: "Ethernet", uplinkV6: "Wi-Fi",
			want: sysport.VPNState{},
		},
		{
			name: "a third adapter holding a default is a full tunnel",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				v4def("Corp VPN", "10.8.0.1"),
			},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{Present: true, FullTunnel: true, Iface: "Corp VPN"},
		},
		{
			name: "our own default and capture routes are not a VPN",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				v4def("dpb0", "10.255.0.2"),
				half("0.0.0.0/1", "dpb0", ""),
				half("128.0.0.0/1", "dpb0", ""),
			},
			uplink: "Wi-Fi", selfIface: "dpb0",
			want: sysport.VPNState{},
		},
		{
			name: "an on-link half-default pair is a full tunnel",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				half("0.0.0.0/1", "wg0", ""),
				half("128.0.0.0/1", "wg0", ""),
			},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{Present: true, FullTunnel: true, Iface: "wg0"},
		},
		{
			// redirect-gateway def1 through a TAP adapter: both halves carry a
			// next hop, so both read back Scoped. scdarwin's `!r.Scoped` filter
			// would miss this entirely.
			name: "a gateway half-default pair is a full tunnel",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				half("0.0.0.0/1", "TAP-Windows", "10.8.0.5"),
				half("128.0.0.0/1", "TAP-Windows", "10.8.0.5"),
			},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{Present: true, FullTunnel: true, Iface: "TAP-Windows"},
		},
		{
			name: "one half alone is a split tunnel we can work alongside",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				half("0.0.0.0/1", "wg0", ""),
			},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{},
		},
		{
			name: "two halves on two different interfaces is not a pair",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				half("0.0.0.0/1", "wg0", ""),
				half("128.0.0.0/1", "wg1", ""),
			},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{},
		},
		{
			name: "a default on an unnamed interface is a naming gap, not a VPN",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.8.0.1"), Scoped: true},
			},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{},
		},
		{
			name: "the v6 half-default pair counts too",
			rs: []sysport.RouteEntry{
				v4def("Wi-Fi", "192.168.1.1"),
				half("::/1", "wg0", ""),
				half("8000::/1", "wg0", ""),
			},
			uplink: "Wi-Fi",
			want:   sysport.VPNState{Present: true, FullTunnel: true, Iface: "wg0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyVPN(tt.rs, tt.uplink, tt.uplinkV6, tt.selfIface)
			if got != tt.want {
				t.Errorf("classifyVPN = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGlobalAddrs(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("192.168.1.50"),   // RFC1918 is still global unicast
		netip.MustParseAddr("169.254.10.1"),   // link-local: not global unicast
		netip.MustParseAddr("127.0.0.1"),      // loopback: not global unicast
		netip.MustParseAddr("2001:db8::1"),    // a v6 global
		netip.MustParseAddr("fd00::1"),        // a ULA: dropped
		netip.MustParseAddr("fe80::1"),        // v6 link-local: not global unicast
		netip.MustParseAddr("::ffff:8.8.8.8"), // 4-in-6 belongs in the v4 list, unmapped
	}
	v4, v6 := globalAddrs(in)

	// Compared as text: a 4-in-6 address that was routed to the v4 list but not
	// Unmap()ped would still be "equal" to its v4 form under some comparisons
	// and would print as "::ffff:8.8.8.8" here, which is exactly the mistake
	// dns.go's splitDNSServersByFamily documents paying for.
	if got, want := addrText(v4), []string{"192.168.1.50", "8.8.8.8"}; !reflect.DeepEqual(got, want) {
		t.Errorf("globalAddrs v4 = %v, want %v", got, want)
	}
	if got, want := addrText(v6), []string{"2001:db8::1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("globalAddrs v6 = %v, want %v", got, want)
	}
}

func addrText(as []netip.Addr) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}

func TestHardwareAddr(t *testing.T) {
	var aa windows.IpAdapterAddresses

	if got := hardwareAddr(&aa); got != "" {
		t.Errorf("an adapter with no hardware address = %q, want %q", got, "")
	}

	copy(aa.PhysicalAddress[:], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01})
	aa.PhysicalAddressLength = 6
	if got, want := hardwareAddr(&aa), "de:ad:be:ef:00:01"; got != want {
		t.Errorf("hardwareAddr = %q, want %q", got, want)
	}

	// A length longer than the array must clamp, not panic. MSDN promises it
	// never exceeds MAX_ADAPTER_ADDRESS_LENGTH; a panic on a user's machine is
	// a worse way to find out that it did than a short string.
	aa.PhysicalAddressLength = uint32(len(aa.PhysicalAddress)) + 4
	if got := hardwareAddr(&aa); len(got) == 0 {
		t.Error("an over-long PhysicalAddressLength produced no address at all")
	}
}
