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
	if st := classifyVPN([]RouteEntry{scopedUtun}, scopedUtun, true, nil, ""); st.Present || st.FullTunnel {
		t.Fatalf("a scoped utun default was classified as a VPN: %+v", st)
	}
	if st := classifyVPN([]RouteEntry{en0}, en0, true, nil, ""); st.Present {
		t.Fatalf("plain ethernet classified as a VPN: %+v", st)
	}
	if st := classifyVPN([]RouteEntry{utun}, utun, true, nil, ""); !st.Present || !st.FullTunnel || st.Iface != "utun3" {
		t.Fatalf("an unscoped utun default must be a full tunnel: %+v", st)
	}
	// A connected VPN that is not carrying the default route is present but not
	// full-tunnel, which is the split-tunnel case we can work alongside.
	st := classifyVPN([]RouteEntry{en0}, en0, true, []NCService{{Status: "Connected", Name: "Split"}}, "")
	if !st.Present || st.FullTunnel || st.ServiceName != "Split" {
		t.Fatalf("split tunnel classified as %+v", st)
	}
	if st := classifyVPN(nil, RouteEntry{}, false, nil, ""); st.Present {
		t.Fatalf("no default route classified as %+v", st)
	}
}

// half returns the WireGuard-style pair a full tunnel installs instead of a
// default route.
func half(iface string, index int, v6 bool) []RouteEntry {
	lo, hi := "0.0.0.0/1", "128.0.0.0/1"
	if v6 {
		lo, hi = "::/1", "8000::/1"
	}
	return []RouteEntry{
		{Dst: netip.MustParsePrefix(lo), Iface: iface, Index: index},
		{Dst: netip.MustParsePrefix(hi), Iface: iface, Index: index},
	}
}

// TestClassifyVPNHalfDefaults is the gate that stops dpb walking into a route
// collision with a VPN. wg-quick, Tailscale, Mullvad and the WireGuard CLI never
// touch 0.0.0.0/0 — they install 0.0.0.0/1 + 128.0.0.0/1 — and they do not
// appear in `scutil --nc list` either, so the classifier that only read the
// unscoped default saw {Present:false, FullTunnel:false} while a half-default
// tunnel carried every packet.
func TestClassifyVPNHalfDefaults(t *testing.T) {
	en0 := RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.0.1"), Iface: "en0", Index: 14}

	t.Run("v4 pair on a utun", func(t *testing.T) {
		rs := append([]RouteEntry{en0}, half("utun6", 20, false)...)
		st := classifyVPN(rs, en0, true, nil, "")
		if !st.Present || !st.FullTunnel || st.Iface != "utun6" {
			t.Fatalf("classifyVPN = %+v, want a full tunnel on utun6", st)
		}
	})

	t.Run("v6 pair on a utun", func(t *testing.T) {
		rs := append([]RouteEntry{en0}, half("utun6", 20, true)...)
		st := classifyVPN(rs, en0, true, nil, "")
		if !st.Present || !st.FullTunnel || st.Iface != "utun6" {
			t.Fatalf("classifyVPN = %+v, want a full tunnel on utun6", st)
		}
	})

	t.Run("one half only is a split tunnel", func(t *testing.T) {
		rs := []RouteEntry{en0, half("utun6", 20, false)[0]}
		if st := classifyVPN(rs, en0, true, nil, ""); st.FullTunnel {
			t.Fatalf("half the address space is not a full tunnel: %+v", st)
		}
	})

	t.Run("halves split across interfaces", func(t *testing.T) {
		rs := []RouteEntry{en0, half("utun6", 20, false)[0], half("utun7", 21, false)[1]}
		if st := classifyVPN(rs, en0, true, nil, ""); st.FullTunnel {
			t.Fatalf("two different tunnels each owning one half is not one full tunnel: %+v", st)
		}
	})

	t.Run("scoped halves are Private-Relay-shaped", func(t *testing.T) {
		rs := []RouteEntry{en0}
		for _, r := range half("utun6", 20, false) {
			r.Scoped = true
			rs = append(rs, r)
		}
		if st := classifyVPN(rs, en0, true, nil, ""); st.FullTunnel {
			t.Fatalf("scoped halves must not be a full tunnel: %+v", st)
		}
	})

	t.Run("not on a tunnel interface", func(t *testing.T) {
		rs := append([]RouteEntry{en0}, half("en1", 15, false)...)
		if st := classifyVPN(rs, en0, true, nil, ""); st.FullTunnel {
			t.Fatalf("half-defaults on a physical interface are not a VPN: %+v", st)
		}
	})

	// Our own capture routes are the identical pair. Seeing them on a
	// network-change re-collect must not make dpb refuse to run alongside itself.
	t.Run("our own utun is excluded", func(t *testing.T) {
		rs := append([]RouteEntry{en0}, half("utun9", 30, false)...)
		if st := classifyVPN(rs, en0, true, nil, "utun9"); st.FullTunnel {
			t.Fatalf("dpb classified its own capture routes as a VPN: %+v", st)
		}
	})
}

// TestCollectFactsHalfTunnelVPN drives the same defect through the real entry
// point, since the gate reads Facts.VPN, not classifyVPN.
func TestCollectFactsHalfTunnelVPN(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.ifaces["utun6"] = &fakeIface{index: 20, mtu: 1420, up: true, addrs: []string{"10.2.0.2/32"}}
	f.routes = append(f.routes, half("utun6", 20, false)...)
	// wg-quick and friends leave scutil --nc empty, so this is the only signal.
	f.vpn = nil

	got, err := CollectFacts(context.Background(), f.env0())
	if err != nil {
		t.Fatalf("CollectFacts: %v", err)
	}
	if !got.VPN.Present || !got.VPN.FullTunnel || got.VPN.Iface != "utun6" {
		t.Fatalf("VPN = %+v, want a full tunnel on utun6", got.VPN)
	}
	if got.Uplink != "en0" {
		t.Fatalf("Uplink = %q, want the physical uplink to still be identified", got.Uplink)
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
