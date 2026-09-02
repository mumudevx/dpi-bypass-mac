package netstate

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestCollectFacts(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	got, err := CollectFacts(context.Background(), f.env0())
	if err != nil {
		t.Fatalf("CollectFacts: %v", err)
	}
	if got.Uplink != "en0" {
		t.Fatalf("Uplink = %q, want en0", got.Uplink)
	}
	if got.Gateway != netip.MustParseAddr("192.168.0.1") {
		t.Fatalf("Gateway = %s", got.Gateway)
	}
	if got.UplinkMAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("UplinkMAC = %q", got.UplinkMAC)
	}
	if !reflect.DeepEqual(got.V4Global, []netip.Addr{netip.MustParseAddr("192.168.0.138")}) {
		t.Fatalf("V4Global = %v", got.V4Global)
	}
	if !reflect.DeepEqual(got.V6Global, []netip.Addr{netip.MustParseAddr("2001:db8:1::5")}) {
		t.Fatalf("V6Global = %v", got.V6Global)
	}
	if !reflect.DeepEqual(got.Services, []string{"Wi-Fi", "Thunderbolt Bridge"}) {
		t.Fatalf("Services = %v", got.Services)
	}
	if got.VPN.Present {
		t.Fatalf("VPN = %+v, want absent", got.VPN)
	}
	if got.CollectedAt.IsZero() {
		t.Fatal("CollectedAt was not set")
	}
}

func TestCollectFactsNeedsARIB(t *testing.T) {
	f := newFakeSystem()
	if _, err := CollectFacts(context.Background(), Env{Runner: f}); err == nil {
		t.Fatal("CollectFacts must refuse to guess the uplink without a RIB")
	}
}

// TestCollectFactsToleratesMissingServiceInfo: proxy mode still works through
// launchctl setenv on a machine whose service list cannot be read, so a failure
// there must degrade rather than abort.
func TestCollectFactsToleratesMissingServiceInfo(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.failNext("networksetup -listnetworkserviceorder", 1)
	f.failNext("scutil --nc list", 1)
	var logged int
	e := f.env0()
	e.Logf = func(string, ...any) { logged++ }

	got, err := CollectFacts(context.Background(), e)
	if err != nil {
		t.Fatalf("CollectFacts: %v", err)
	}
	if len(got.Services) != 0 {
		t.Fatalf("Services = %v, want empty", got.Services)
	}
	if logged < 2 {
		t.Fatalf("both failures must be reported to the user, logged %d", logged)
	}
}

func TestCollectFactsFullTunnelVPN(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.ifaces["utun3"] = &fakeIface{index: 21, mtu: 1400, up: true, addrs: []string{"10.8.0.2/24"}}
	// A full-tunnel VPN owns the unscoped default.
	f.routes[0] = RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Iface: "utun3", Index: 21}
	f.vpn = []NCService{{Enabled: true, Status: "Connected", ID: "1", Type: "IPSec", Name: "Corp"}}

	got, err := CollectFacts(context.Background(), f.env0())
	if err != nil {
		t.Fatalf("CollectFacts: %v", err)
	}
	if !got.VPN.Present || !got.VPN.FullTunnel {
		t.Fatalf("VPN = %+v, want a full tunnel", got.VPN)
	}
	if got.VPN.Iface != "utun3" || got.VPN.ServiceName != "Corp" {
		t.Fatalf("VPN = %+v", got.VPN)
	}
}

func TestClassifyVPN(t *testing.T) {
	scopedUtun := RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Iface: "utun0", Scoped: true}
	en0 := RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Iface: "en0"}
	utun := RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Iface: "utun3"}

	// iCloud Private Relay installs scoped utun defaults and is not a VPN in the
	// sense that matters: it does not own the unscoped default.
	if st := classifyVPN(scopedUtun, true, nil); st.Present || st.FullTunnel {
		t.Fatalf("a scoped utun default was classified as a VPN: %+v", st)
	}
	if st := classifyVPN(en0, true, nil); st.Present {
		t.Fatalf("plain ethernet classified as a VPN: %+v", st)
	}
	if st := classifyVPN(utun, true, nil); !st.Present || !st.FullTunnel || st.Iface != "utun3" {
		t.Fatalf("an unscoped utun default must be a full tunnel: %+v", st)
	}
	// A connected VPN that is not carrying the default route is present but not
	// full-tunnel, which is the split-tunnel case we can work alongside.
	st := classifyVPN(en0, true, []NCService{{Status: "Connected", Name: "Split"}})
	if !st.Present || st.FullTunnel || st.ServiceName != "Split" {
		t.Fatalf("split tunnel classified as %+v", st)
	}
	if st := classifyVPN(RouteEntry{}, false, nil); st.Present {
		t.Fatalf("no default route classified as %+v", st)
	}
}

func TestIsTunnelIface(t *testing.T) {
	for _, name := range []string{"utun0", "ipsec0", "ppp0", "tun3"} {
		if !isTunnelIface(name) {
			t.Fatalf("%s should be a tunnel", name)
		}
	}
	for _, name := range []string{"en0", "bridge0", "lo0", ""} {
		if isTunnelIface(name) {
			t.Fatalf("%s should not be a tunnel", name)
		}
	}
}

func TestGlobalAddrsSkipsULAsAndLinkLocals(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.ifaces["en0"].addrs = []string{
		"192.168.0.138/24",
		"fe80::1/64",       // link local
		"fd00:d9b::1/64",   // ULA: routable in our tunnel, never a global uplink address
		"2001:db8:1::5/64", // global
	}
	got, err := CollectFacts(context.Background(), f.env0())
	if err != nil {
		t.Fatalf("CollectFacts: %v", err)
	}
	if !reflect.DeepEqual(got.V6Global, []netip.Addr{netip.MustParseAddr("2001:db8:1::5")}) {
		t.Fatalf("V6Global = %v, want only the global address", got.V6Global)
	}
}
