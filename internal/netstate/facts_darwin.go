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
	Uplink      string
	Gateway     netip.Addr
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
	def, ok, err := e.RIB.Default()
	if err != nil {
		return nil, fmt.Errorf("netstate: read default route: %w", err)
	}
	f := &Facts{CollectedAt: time.Now()}
	if ok {
		f.Uplink, f.Gateway = def.Iface, def.Gateway
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
	f.VPN = classifyVPN(def, ok, ncs)
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

// classifyVPN decides whether a VPN is present and whether it is full-tunnel.
//
// Two independent signals: scutil --nc reports configured VPN services and
// their connection state, and the RIB says which interface owns the unscoped
// default route. Only the second can distinguish "a VPN is connected" from "a
// VPN is carrying all my traffic", and only the second sees a VPN configured
// outside the system's network-extension framework.
func classifyVPN(def RouteEntry, haveDefault bool, ncs []NCService) VPNState {
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
	}
	return st
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
