package netstate

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// VPNState describes whether a VPN is in the way. FullTunnel is the one that
// changes behaviour: if something else owns the unscoped default route, our
// capture routes and our scoped uplink default cannot be made to work, and the
// honest answer is to stop rather than report success.
type VPNState struct {
	Present     bool
	FullTunnel  bool
	Iface       string
	ServiceName string
}

// Facts is the snapshot of the machine's network identity that every mutation
// is planned against. It is a value, collected once per network change, so a
// mid-run reconfiguration cannot make two Ops disagree about which interface
// the uplink is.
type Facts struct {
	Uplink  string
	Gateway netip.Addr
	// UplinkV6 and GatewayV6 are the machine's real IPv6 next hop, read the
	// same way and kept separate because they are frequently a different
	// interface — or absent entirely on a v4-only line. TUN mode needs them to
	// scope an IPv6 default to the uplink before ::/1 and 8000::/1 point at the
	// tunnel; without that route our own upstream v6 sockets would be pulled
	// back into our own netstack and loop.
	UplinkV6    string
	GatewayV6   netip.Addr
	UplinkMAC   string
	V4Global    []netip.Addr
	V6Global    []netip.Addr
	Services    []string
	VPN         VPNState
	CollectedAt time.Time
}

// CollectFacts reads the machine's current network identity. The uplink comes
// from the kernel routing table rather than from networksetup's service order,
// because the service order says what macOS would prefer and the RIB says what
// is actually carrying traffic.
func CollectFacts(ctx context.Context, e Env) (*Facts, error) {
	if e.RIB == nil {
		return nil, fmt.Errorf("netstate: cannot collect facts without a RIB reader")
	}
	// One read of the whole table, not two. The uplink and the VPN verdict have
	// to describe the same instant: Facts exists so a mid-run reconfiguration
	// cannot make two Ops disagree, and reading the RIB twice would reintroduce
	// exactly that disagreement between the default route and the half-default
	// pair classifyVPN now looks for.
	rs, err := e.RIB.Routes()
	if err != nil {
		return nil, fmt.Errorf("netstate: read routing table: %w", err)
	}
	def, ok, err := pickDefault(rs, "")
	if err != nil {
		return nil, fmt.Errorf("netstate: read default route: %w", err)
	}
	f := &Facts{CollectedAt: time.Now()}
	if ok {
		f.Uplink, f.Gateway = def.Iface, def.Gateway
	}
	if v6, ok6 := pickDefaultV6(rs); ok6 {
		f.UplinkV6, f.GatewayV6 = v6.Iface, v6.Gateway
	}

	if f.Uplink != "" {
		in, found, err := findInterface(f.Uplink)
		if err != nil {
			return nil, err
		}
		if found {
			f.UplinkMAC = in.HardwareAddr.String()
			v4, v6, err := globalAddrs(in)
			if err != nil {
				return nil, err
			}
			f.V4Global, f.V6Global = v4, v6
		}
	}

	// A machine with no configured services is unusual but not fatal — proxy
	// mode still works through launchctl setenv — so a failure here is recorded
	// and not returned.
	if svcs, err := ListServices(ctx, e); err != nil {
		e.logf("netstate: %v", err)
	} else {
		f.Services = serviceNames(svcs)
	}

	ncs, err := readNCList(ctx, e)
	if err != nil {
		e.logf("netstate: %v", err)
	}
	f.VPN = classifyVPN(rs, def, ok, ncs, e.SelfIface)
	return f, nil
}

func globalAddrs(in *net.Interface) (v4, v6 []netip.Addr, err error) {
	addrs, err := interfaceAddrser(in)
	if err != nil {
		return nil, nil, fmt.Errorf("netstate: read addresses of %s: %w", in.Name, err)
	}
	for _, a := range addrs {
		ip, ok := addrOfNetAddr(a)
		if !ok || !ip.IsGlobalUnicast() {
			continue
		}
		if ip.Is4() || ip.Is4In6() {
			v4 = append(v4, ip.Unmap())
			continue
		}
		// A ULA is routable inside the tunnel we build, never a global uplink
		// address, and treating it as one would make the AAAA policy wrong.
		if ip.IsPrivate() {
			continue
		}
		v6 = append(v6, ip)
	}
	return v4, v6, nil
}

// halfDefaultPairs are the prefix pairs that between them cover the whole
// address space without touching 0.0.0.0/0 or ::/0.
//
// This is the idiom wg-quick, Tailscale, Mullvad and the WireGuard CLI use, and
// they use it deliberately: installing the two halves leaves the real default
// route in place, so the tunnel can be torn down without the machine losing its
// gateway. A classifier that only inspects the unscoped default therefore never
// sees the most common macOS full tunnel — and those tools do not appear in
// `scutil --nc list` either, so the second signal is silent too.
var halfDefaultPairs = [][2]netip.Prefix{
	{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")},
	{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")},
}

// classifyVPN decides whether a VPN is present and whether it is full-tunnel.
//
// Three signals: scutil --nc reports configured VPN services and their
// connection state; the RIB says which interface owns the unscoped default
// route; and the RIB also shows the half-default pair a WireGuard-style tunnel
// installs instead of a default. Only the RIB can distinguish "a VPN is
// connected" from "a VPN is carrying all my traffic", and only the RIB sees a
// VPN configured outside the system's network-extension framework.
//
// selfIface names our own utun, if we have one. Our capture routes are the same
// half-default pair (docs/PLAN.md's mutated-state table, row 8), so without
// excluding it a network-change re-collect would classify dpb as a full-tunnel
// VPN and refuse to run alongside itself.
func classifyVPN(rs []RouteEntry, def RouteEntry, haveDefault bool, ncs []NCService, selfIface string) VPNState {
	var st VPNState
	for _, s := range ncs {
		if s.Connected() {
			st.Present = true
			st.ServiceName = s.Name
			break
		}
	}
	if haveDefault && isTunnelIface(def.Iface) && !def.Scoped {
		st.Present = true
		st.FullTunnel = true
		st.Iface = def.Iface
		return st
	}
	if iface, ok := halfTunnelIface(rs, selfIface); ok {
		st.Present = true
		st.FullTunnel = true
		st.Iface = iface
	}
	return st
}

// halfTunnelIface reports the tunnel interface that owns both halves of a
// half-default pair, if any. Both halves must be unscoped and on the same
// interface: a scoped half is Private-Relay-shaped, and one half on its own
// covers only part of the address space, which is a split tunnel we can work
// alongside.
func halfTunnelIface(rs []RouteEntry, selfIface string) (string, bool) {
	for _, pair := range halfDefaultPairs {
		lower := map[string]bool{}
		for _, r := range rs {
			if r.Dst != pair[0] || r.Scoped || r.Iface == selfIface || !isTunnelIface(r.Iface) {
				continue
			}
			lower[r.Iface] = true
		}
		if len(lower) == 0 {
			continue
		}
		for _, r := range rs {
			if r.Dst != pair[1] || r.Scoped {
				continue
			}
			if lower[r.Iface] {
				return r.Iface, true
			}
		}
	}
	return "", false
}

// isTunnelIface recognises the interface-name families macOS gives to tunnels.
// utun covers both real VPNs and Apple's own iCloud Private Relay, which is why
// the caller must also check that the interface owns the *unscoped* default:
// Private Relay installs scoped routes only.
func isTunnelIface(name string) bool {
	for _, p := range []string{"utun", "ipsec", "ppp", "gpd", "tun"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
