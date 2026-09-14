//go:build windows

package scwindows

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

type factsCtl struct{ p *port }

var _ sysport.FactsCollector = factsCtl{}

// Collect reads the machine's current network identity.
//
// Two observers, in this order: the routing table (through the RIB, which is
// GetIpForwardTable2) names the uplink, its gateways and any foreign default;
// GetAdaptersAddresses then fills in the MAC and the global addresses of the
// interface the routing table named. Everything that has to agree — which
// interface is "the" uplink, which interface a VPN is on — comes out of ONE
// routing-table read, for the reason scdarwin's collectFacts gives: Facts
// exists so a mid-run reconfiguration cannot make two Ops disagree, and a
// second read would reintroduce exactly that disagreement.
//
// selfIface names the tunnel this run owns, or "" before we have one. See
// classifyVPN for why the classifier cannot work without being told.
func (c factsCtl) Collect(_ context.Context, selfIface string) (*sysport.Facts, error) {
	if c.p.rib == nil {
		return nil, fmt.Errorf("netstate: cannot collect facts without a RIB reader")
	}
	rs, err := c.p.rib.Routes()
	if err != nil {
		return nil, fmt.Errorf("netstate: read routing table: %w", err)
	}

	f := &sysport.Facts{CollectedAt: time.Now()}

	// pickDefault, NOT GetBestRoute2, and that is a deliberate choice against
	// the more accurate answer.
	//
	// GetBestRoute2 would name the interface the forwarding engine ACTUALLY
	// selects, which is still better information: rib.go's pickDefault ranks
	// several defaults by interface metric, but the row's own metric offset
	// does not survive into sysport.RouteEntry and so is not in the ranking.
	//
	// It is not used here because Facts.Uplink is not the only place this
	// question gets asked. dnsCtl.Live (dns.go) independently re-asks "which
	// interface is the default one" through c.p.rib.Default() — i.e. through
	// pickDefault — to decide whose resolvers to verify, and cliapp/tunrun.go
	// hands dnsCtl.Set the answer THIS function produced (Facts.Services). If
	// the two used different selectors they would disagree on a machine with
	// more than one default route, and every DNS verify would then fail on an
	// adapter that was correctly configured. An uplink that agrees with the
	// verifier is worth more here than an uplink that is independently more
	// accurate, so both sides call pickDefault WITH THE SAME METRIC LOOKUP and
	// neither claims more than rib.go already claims for it.
	//
	// interfaceMetrics() is built once and shared by both picks below, so the
	// v4 and v6 uplinks are chosen against one snapshot of the interface
	// metrics — the same "everything that has to agree comes out of one read"
	// rule this function applies to the routing table.
	ifMetric := interfaceMetrics()
	def, ok, err := pickDefault(rs, "", ifMetric)
	if err != nil {
		return nil, fmt.Errorf("netstate: read default route: %w", err)
	}
	if ok {
		f.Uplink, f.Gateway = def.Iface, def.Gateway
	}
	if v6, ok6 := pickDefaultV6(rs, ifMetric); ok6 {
		f.UplinkV6, f.GatewayV6 = v6.Iface, v6.Gateway
	}
	f.Services = uplinkServices(f.Uplink, f.UplinkV6)

	if f.Uplink != "" {
		// One GetAdaptersAddresses read, reusing iface.go's adapterAddresses
		// and findAdapter rather than net.Interfaces(): net.Interfaces on
		// Windows is itself a GetAdaptersAddresses call (verified by reading
		// $GOROOT/src/net/interface_windows.go — see rib.go's interfaceLister
		// comment), so going through it would cost the same syscall and then
		// a SECOND one for the addresses, with the MAC and the address list
		// describing two different instants.
		aas, err := adapterAddresses()
		if err != nil {
			// Fatal, matching scdarwin: there its findInterface propagates a
			// net.Interfaces() failure rather than reporting an uplink with no
			// addresses. A Facts whose V4Global is empty is not distinguishable
			// by its callers from a machine that genuinely has no global
			// address, and the AAAA policy is decided off V6Global.
			return nil, err
		}
		// An adapter the routing table named but the adapter list does not have
		// is tolerated, matching scdarwin's `found == false` branch: an
		// interface can go away between the two reads, and the uplink NAME is
		// still the best thing we know about this machine.
		if aa, found := findAdapter(aas, f.Uplink); found {
			f.UplinkMAC = hardwareAddr(aa)
			f.V4Global, f.V6Global = globalAddrs(unicastAddrsOf(aa))
		}
	}

	f.VPN = classifyVPN(rs, f.Uplink, f.UplinkV6, selfIface)
	return f, nil
}

// uplinkServices is Facts.Services on Windows: the FriendlyName of the adapter
// carrying the default route, plus the IPv6 uplink's when that is a different
// adapter.
//
// # Why adapter names and not proxyCtl's pseudo-service
//
// Facts.Services has exactly two consumers, and they want opposite things from
// a name that is not an adapter:
//
//   - internal/netstate/op_dns.go passes each entry to DNSController.Set and
//     Configured. On Windows those become `netsh interface ipv4 set dnsservers
//     name=<...>` and a findAdapter lookup by FriendlyName (dns.go), so a name
//     that is not an adapter's FriendlyName fails — Configured says so BY NAME
//     ("interface %q not found for a DNS capture") precisely so that a wiring
//     bug here cannot be mistaken for an empty resolver list.
//   - internal/netstate/op_proxy.go passes each entry to the ProxyController,
//     where every writer accepts and ignores it: Windows keeps ONE proxy
//     configuration per user, which is why windows.go withholds
//     sysport.CapPerService permanently.
//
// So adapter names are the only choice that both consumers can use, and
// proxyCtl.Services' single pseudo-service ("the current user's Internet
// Settings") must never end up here. That pseudo-service still exists and is
// still right for what it names — it is what dpb PRINTS when it says which
// thing a proxy setting was applied to — but it is not an interface, and
// nothing in this file produces it.
//
// # The fallback this does not reach, and the one case that still can
//
// dnsOp.prepare falls back to Proxy().Services() when it is given no service
// list, which on Windows would hand the DNS controller that pseudo-service.
// The real path never gets there: cliapp/tunrun.go sets capt.Services from
// Facts.Services, and this function returns a non-empty list whenever the
// machine has a default route at all.
//
// A machine with NO default route is the residual case: Services is empty,
// dnsOp falls back, and dnsCtl.Configured refuses the pseudo-service by name.
// That is left as a loud failure rather than papered over, because a machine
// with no default route has no uplink for dpb to scope a route to and cannot
// run TUN mode regardless; a DNS Op that "succeeded" there would be the
// silent-skip this project refuses.
//
// # Why the uplink only, and not every adapter
//
// scdarwin's Facts.Services is every ENABLED network service, because that is
// what `networksetup -listallnetworkservices` enumerates: a short, curated,
// user-facing list. GetAdaptersAddresses is not that list. It reports the
// loopback pseudo-interface, WFP/Wi-Fi-Direct virtual adapters, Hyper-V and
// VirtualBox host-only adapters, and every disconnected NIC — names `netsh
// interface ipv4 set dnsservers` will refuse, and a refusal aborts dnsOp.Apply
// for the whole machine (dnsOp.Apply returns on the first Set error). Setting
// resolvers on adapters the user never asked about would also widen what a
// crashed run leaves behind. The uplink is the adapter dnsCtl.Live verifies
// against, so it is both the smallest and the only self-consistent answer.
func uplinkServices(uplink, uplinkV6 string) []string {
	var out []string
	if uplink != "" {
		out = append(out, uplink)
	}
	if uplinkV6 != "" && uplinkV6 != uplink {
		out = append(out, uplinkV6)
	}
	return out
}

// pickDefaultV6 finds the IPv6 default route.
//
// It is separate from pickDefault for scdarwin's reason: that one deliberately
// prefers IPv4 because its callers use it to identify THE uplink, and the v6
// next hop is a different question with a frequently different answer.
//
// What could NOT be carried across from scdarwin is its filter. scdarwin skips
// `r.Scoped` rows, because on macOS Scoped carries RTF_IFSCOPE and an unscoped
// default is the system's own. On Windows, rib.go defines Scoped as THIS ROW
// HAS A NEXT HOP (there is no RTF_IFSCOPE and no unbound route to distinguish),
// so `!r.Scoped` means "no gateway" here — the exact opposite of what scdarwin
// is asking for, and combined with its own `r.Gateway.IsValid()` check it would
// match nothing at all, on every machine, forever. This asks only for what the
// caller actually needs: a v6 default with a next hop that
// sysport.RouteSpec{Dst, Gw, Iface} can be built from.
//
// It ranks by ifMetric for pickDefault's reason and no other: a dual-homed
// machine has two ::/0 rows as routinely as it has two 0.0.0.0/0 rows, and
// naming the idle adapter here puts Facts.GatewayV6 — and therefore the v6
// scoped default cliapp builds from it — on the wrong NIC. A nil ifMetric
// leaves the first-seen order deciding, exactly as before.
func pickDefaultV6(rs []sysport.RouteEntry, ifMetric ifaceMetricFunc) (sysport.RouteEntry, bool) {
	var best sysport.RouteEntry
	var bestMetric uint32
	found := false
	for _, r := range rs {
		if r.Dst.Bits() != 0 || r.Dst.Addr().Is4() {
			continue
		}
		if !r.Gateway.IsValid() {
			// A default with no next hop is an on-link route; it cannot be
			// turned into the gateway route Facts.GatewayV6 exists to build.
			continue
		}
		if m := routeMetric(r, ifMetric); !found || m < bestMetric {
			best, bestMetric, found = r, m, true
		}
	}
	return best, found
}

// halfDefaultPairs are the prefix pairs that between them cover the whole
// address space without touching 0.0.0.0/0 or ::/0.
//
// The idiom is not macOS-specific: it is OpenVPN's `redirect-gateway def1`,
// which is where it comes from, and wg-quick, Tailscale and Mullvad all ship
// it on Windows too. Installing the two halves leaves the real default route
// in place, so the tunnel can be torn down without the machine losing its
// gateway — and a classifier that only inspects 0.0.0.0/0 never sees it.
var halfDefaultPairs = [][2]netip.Prefix{
	{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")},
	{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")},
}

// classifyVPN decides whether something other than the uplink owns the whole
// address space.
//
// # What FullTunnel means and why it is the field that matters
//
// sysport.VPNState.FullTunnel is the bit that changes behaviour: netwatch's
// ClassifyVPN turns it into ErrFullTunnelVPN (exit code 5) for any front end
// whose correctness depends on owning routes. Something else owning the
// unscoped default means our capture routes and our scoped uplink default
// cannot both be made to work, and the honest answer is to stop rather than
// print "Ready" while capturing nothing.
//
// # The two shapes, and what Windows cannot tell apart
//
// Signal one is the half-default pair above: ONE interface owning both halves
// of a pair covers everything without touching the default, and nothing but a
// capture-everything tool installs both.
//
// Signal two is the parent shape: a default route (0.0.0.0/0 or ::/0) on an
// interface that is neither uplink, uplinkV6, nor selfIface.
//
// selfIface is a parameter at all because our OWN capture routes are the same
// half-default pair (docs/PLAN.md's mutated-state table, row 8) and our own
// scoped uplink default is a 0.0.0.0/0 row: without being told which tunnel is
// ours, a network-change re-collect would classify dpb as a full-tunnel VPN and
// refuse to run alongside itself.
//
// # The false positive, named rather than hidden
//
// scdarwin narrows signal two with isTunnelIface — utun/ipsec/ppp/gpd/tun — so
// a second PHYSICAL default there does not read as a VPN. Windows has no
// equivalent: an adapter's name is its FriendlyName, which is user-editable and
// carries no convention ("Ethernet 2" and "Wi-Fi" are as likely on a tunnel as
// on a NIC), so there is no name test to apply. The consequence is stated
// rather than papered over: a genuinely dual-homed machine — a docked laptop
// with Ethernet up and Wi-Fi still associated, both holding a default route —
// reads as a full-tunnel VPN and `dpb run --tun` refuses with exit code 5.
// `--allow-vpn` is the escape hatch that already exists for it.
//
// That direction was chosen deliberately. The opposite error — not noticing a
// real full tunnel — is the one docs/PLAN.md's verification contract exists to
// prevent, and it is silent: the user believes dpb is bypassing, is not, and
// finds out from a website that does not load. A refusal is loud, names the
// interface, and has a documented override. Plan 5 puts a binary on a real
// Windows 11 machine; how often the dual-homed shape actually occurs there is
// one of the things it has to find out.
//
// ServiceName is left empty: Windows has no `scutil --nc list` equivalent this
// package reads, so there is no configured-VPN name to report alongside the
// interface. netwatch's nameOr already falls back to Iface for exactly this.
func classifyVPN(rs []sysport.RouteEntry, uplink, uplinkV6, selfIface string) sysport.VPNState {
	if iface, ok := foreignDefaultIface(rs, uplink, uplinkV6, selfIface); ok {
		return sysport.VPNState{Present: true, FullTunnel: true, Iface: iface}
	}
	if iface, ok := halfTunnelIface(rs, selfIface); ok {
		return sysport.VPNState{Present: true, FullTunnel: true, Iface: iface}
	}
	return sysport.VPNState{}
}

// foreignDefaultIface reports the interface of a default route that belongs to
// neither uplink we found nor to us.
//
// Both uplinks are excluded, not just the v4 one. Facts.UplinkV6 exists because
// the IPv6 next hop is "frequently a different interface" (sysport.Facts), so a
// ::/0 on that other interface is the machine's normal v6 path and must not
// read as a VPN.
//
// A row whose interface could not be named is skipped: rib.go fills
// RouteEntry.Iface from an index/name map that can miss an adapter which
// appeared between the cache refresh and the read, and "" matches no uplink, so
// treating it as foreign would fabricate a VPN out of a naming gap.
func foreignDefaultIface(rs []sysport.RouteEntry, uplink, uplinkV6, selfIface string) (string, bool) {
	for _, r := range rs {
		if r.Dst.Bits() != 0 || r.Iface == "" {
			continue
		}
		if r.Iface == uplink || r.Iface == uplinkV6 || r.Iface == selfIface {
			continue
		}
		return r.Iface, true
	}
	return "", false
}

// halfTunnelIface reports the interface that owns both halves of a
// half-default pair, if any.
//
// Two differences from scdarwin's version, both forced by Windows:
//
//   - It does not filter on Scoped. There, a scoped half is Private-Relay-
//     shaped and excluded; here Scoped means "has a next hop" (rib.go), and a
//     tunnel installs its halves EITHER on-link (Wintun-class adapters, which
//     have no link layer to resolve a next hop on) OR through the tunnel's own
//     gateway (TAP-class adapters, which do). Filtering on Scoped in either
//     direction would blind this to half the tunnels on the platform.
//   - It does not require the interface to look like a tunnel. There is no
//     Windows name convention to test; see classifyVPN.
//
// Both halves must be on the SAME interface: one half on its own covers only
// part of the address space, which is a split tunnel we can work alongside.
func halfTunnelIface(rs []sysport.RouteEntry, selfIface string) (string, bool) {
	for _, pair := range halfDefaultPairs {
		lower := map[string]bool{}
		for _, r := range rs {
			if r.Dst != pair[0] || r.Iface == "" || r.Iface == selfIface {
				continue
			}
			lower[r.Iface] = true
		}
		if len(lower) == 0 {
			continue
		}
		for _, r := range rs {
			if r.Dst == pair[1] && lower[r.Iface] {
				return r.Iface, true
			}
		}
	}
	return "", false
}

// globalAddrs splits an adapter's unicast addresses into the globally routable
// v4 and v6 ones, applying scdarwin's globalAddrs rules unchanged.
//
// A ULA (fc00::/7, netip.Addr.IsPrivate) is dropped rather than counted as a
// v6 global: it is routable inside the tunnel we build, never an uplink
// address, and treating it as one would make the AAAA policy wrong.
func globalAddrs(addrs []netip.Addr) (v4, v6 []netip.Addr) {
	for _, ip := range addrs {
		if !ip.IsGlobalUnicast() {
			continue
		}
		if ip.Is4() || ip.Is4In6() {
			v4 = append(v4, ip.Unmap())
			continue
		}
		if ip.IsPrivate() {
			continue
		}
		v6 = append(v6, ip)
	}
	return v4, v6
}

// hardwareAddr formats an adapter's MAC the way scdarwin does — through
// net.HardwareAddr.String(), so the two platforms produce byte-identical text
// for the same address rather than two spellings of it.
//
// MSDN, IP_ADAPTER_ADDRESSES: PhysicalAddress is "the Media Access Control
// (MAC) address for the adapter" and PhysicalAddressLength "the length, in
// bytes, of the hardware address". The length is clamped to the array before
// slicing: the field is MAX_ADAPTER_ADDRESS_LENGTH bytes wide and MSDN promises
// no more than that, but a length that exceeded it would be an out-of-range
// panic on a user's machine rather than a wrong string.
//
// An adapter with no hardware address answers "", which is what scdarwin's
// net.Interface.HardwareAddr.String() answers for the same case. That is normal
// for the L3 tunnel adapters dpb itself opens, and it is not an error.
func hardwareAddr(aa *windows.IpAdapterAddresses) string {
	n := int(aa.PhysicalAddressLength)
	if n <= 0 {
		return ""
	}
	if n > len(aa.PhysicalAddress) {
		n = len(aa.PhysicalAddress)
	}
	return net.HardwareAddr(aa.PhysicalAddress[:n]).String()
}
