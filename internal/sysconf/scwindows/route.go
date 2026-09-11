//go:build windows

package scwindows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// routeCtl writes routes with CreateIpForwardEntry2/DeleteIpForwardEntry2 and
// hands out the GetIpForwardTable2 reader to verify them.
//
// Unlike scdarwin's routeCtl, the write and the read share an API family; the
// package comment states that plainly and says why route.exe was not the
// answer. What Windows gives back in exchange is a typed error code on every
// write, where macOS route(8) gives exit 0 and a sentence on stderr.
type routeCtl struct{ p *port }

var _ sysport.RouteController = routeCtl{}

// Field values that are the same for every row this package creates. They are
// named constants rather than literals in the struct because each one is a
// claim about the MSDN contract, and a claim wants somewhere to write down why.
const (
	// routeLifetimeInfinite fills both ValidLifetime and PreferredLifetime.
	// MSDN, MIB_IPFORWARD_ROW2: of each, "A value of 0xffffffff is considered
	// to be infinite." Using it for both also satisfies
	// CreateIpForwardEntry2's ERROR_INVALID_PARAMETER condition "if the
	// PreferredLifetime member ... is greater than the ValidLifetime member",
	// since equal is not greater. A route dpb installs must outlive the run
	// that installed it right up to teardown; an expiring one would vanish
	// mid-session and take the capture with it.
	routeLifetimeInfinite = ^uint32(0)

	// routeMetricOffset is 0, meaning "no offset".
	//
	// MSDN is explicit that Metric here is not the route's metric: "the actual
	// route metric used to compute the route preference is the summation of
	// interface metric specified in the Metric member of the
	// MIB_IPINTERFACE_ROW structure and the route metric offset specified in
	// this member." Zero therefore means the route is preferred exactly as much
	// as its interface is, which is the neutral choice and the one a capture
	// route needs — it must not be deprioritised relative to anything else on
	// the same adapter.
	//
	// MSDN also says "If this metric is not used, its value should be set to
	// -1", i.e. 0xffffffff. That sentinel is NOT used here: nothing in the
	// documentation says how route selection treats it, and the two readings —
	// "ignore this field" and "add four billion to the interface metric" — have
	// opposite consequences for whether our route wins. Zero has one reading.
	routeMetricOffset = 0

	// routeSitePrefixLength is 0.
	//
	// CreateIpForwardEntry2 returns ERROR_INVALID_PARAMETER "if the
	// SitePrefixLength in the MIB_IPFORWARD_ROW2 is greater than the prefix
	// length specified in the DestinationPrefix", and 0 is the one value that
	// is never greater than any prefix length, including a default route's 0.
	// (MSDN elsewhere calls 255 "commonly used to represent an illegal value";
	// 255 is greater than every legal prefix length, so it is not available
	// here.)
	routeSitePrefixLength = 0
)

func (c routeCtl) Add(ctx context.Context, s sysport.RouteSpec) error {
	row, err := c.row(s)
	if err != nil {
		return err
	}
	if err := CreateIpForwardEntry2(row); err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			// This is the Windows analogue of macOS route(8)'s exit-0 "File
			// exists" liar, and it is returned as an ERROR for the same reason
			// netstate's routeOp.mutated() exists: MSDN says the code means
			// "the DestinationPrefix member ... is a duplicate of an existing
			// IP route entry on the interface specified", i.e. SOMEBODY ELSE
			// ALREADY OWNS THAT DESTINATION ON THAT INTERFACE. Reporting
			// success here would set routeOp.added, and rollback would then
			// issue a delete against a row we did not create — a coexisting
			// VPN's default, most likely.
			return fmt.Errorf("netstate: %s already carries a route to %s installed by something else "+
				"(CreateIpForwardEntry2 refused it as a duplicate); leaving it alone: %w", s.Iface, s.Dst, err)
		}
		return fmt.Errorf("netstate: add route %s on %s: %w", s.Dst, s.Iface, err)
	}
	return nil
}

// Delete issues the delete and reports what IP Helper said. The caller decides
// what that means; netstate's routeOp.Revert logs the error and lets its
// VerifyReverted RIB read make the call, because an already-absent route and a
// refused delete look alike from here.
//
// Delete is safer than its macOS counterpart in one specific way worth naming.
// MSDN: "The DeleteIpForwardEntry2 function will fail if the DestinationPrefix
// and NextHop members ... do not match an existing IP route entry on the
// interface specified in the InterfaceLuid or InterfaceIndex members." macOS
// resolves RTM_DELETE by destination and netmask alone — the link gateway that
// `-interface` supplies is never compared — which is why routeOp.Revert reads
// the RIB before deleting at all. That pre-check is still right and still runs;
// this API simply cannot remove a coexisting tunnel's route at the same
// destination on a different interface even if it were asked to.
func (c routeCtl) Delete(ctx context.Context, s sysport.RouteSpec) error {
	row, err := c.row(s)
	if err != nil {
		return err
	}
	if err := DeleteIpForwardEntry2(row); err != nil {
		return fmt.Errorf("netstate: delete route %s on %s: %w", s.Dst, s.Iface, err)
	}
	return nil
}

// RIB is the verifier. It reads through GetIpForwardTable2 rather than
// re-reading the row we wrote; see the package comment on how much weaker that
// is than scdarwin's split, and what GetBestRoute2 adds on top.
func (c routeCtl) RIB() sysport.RIBReader { return c.p.rib }

// row resolves s's interface name to an index and builds the row.
func (c routeCtl) row(s sysport.RouteSpec) (*windows.MibIpForwardRow2, error) {
	idx, err := ifaceIndex(s.Iface)
	if err != nil {
		return nil, err
	}
	return routeRow(s, idx)
}

// ifaceIndex resolves an interface name to its index through the same
// enumeration the RIB reader uses, so a name that resolves for one resolves for
// the other.
func ifaceIndex(name string) (uint32, error) {
	if name == "" {
		// Reaching here means routeRow's shape check was bypassed; keep the
		// refusal rather than looking up the empty name and getting index 0,
		// which CreateIpForwardEntry2 reads as "unspecified".
		return 0, errRouteNeedsIface
	}
	ifs, err := interfaceLister()
	if err != nil {
		return 0, fmt.Errorf("netstate: enumerate interfaces: %w", err)
	}
	for _, in := range ifs {
		if in.Name == name {
			return uint32(in.Index), nil
		}
	}
	return 0, fmt.Errorf("netstate: no interface named %q on this machine", name)
}

// errRouteNeedsIface is the refusal for RouteSpec's third shape.
//
// sysport.RouteSpec documents three shapes. Two map onto MIB_IPFORWARD_ROW2
// exactly (see routeRow). The third — Gw valid, Iface empty, "a plain gateway
// route" — does not, and is refused here rather than approximated:
//
//   - Windows has no unbound route. CreateIpForwardEntry2 returns
//     ERROR_INVALID_PARAMETER when "both the InterfaceLuid or InterfaceIndex
//     members ... were unspecified", so an interface must be invented from
//     somewhere (the gateway's own best route, say) before the row can be
//     written at all.
//   - Whatever interface were invented, the resulting row is
//     INDISTINGUISHABLE from the row the first shape writes: an interface and a
//     next hop. So it reads back with Scoped true (see routeEntryFrom), while
//     netstate's matchRoute computes wantScoped = `gw.IsValid() && iface != ""`
//     = false for this shape and rejects the match.
//
// The route would therefore be installed on the machine and then fail
// verification forever — mutated() true, Verify false, and a real row left
// behind on every attempt. Refusing before the write is the only outcome that
// leaves the machine as it found it, and it names the fix: give the interface.
var errRouteNeedsIface = errors.New(
	"netstate: Windows cannot install a gateway route without naming an interface " +
		"(MIB_IPFORWARD_ROW2 requires InterfaceLuid or InterfaceIndex), and a route added " +
		"on an interface Windows chose could never be verified against the request; " +
		"set RouteSpec.Iface")

// routeRow maps a RouteSpec onto a MIB_IPFORWARD_ROW2 for the interface at
// ifIndex. It is pure so the mapping can be pinned by a test on a machine that
// is not Windows.
//
// # The three RouteSpec shapes
//
//	Gw valid, Iface set    scoped gateway route   NextHop = Gw
//	                       (the uplink default)   InterfaceIndex = Iface
//	                                              reads back Scoped=true
//
//	Gw invalid, Iface set  interface route        NextHop = the UNSPECIFIED
//	                       (the capture routes)     address of the destination's
//	                                                family: 0.0.0.0 or ::
//	                                              InterfaceIndex = Iface
//	                                              reads back Scoped=false
//
//	Gw valid, Iface empty  plain gateway route    REFUSED — errRouteNeedsIface
//
// The interface-route case is the one to get right, and it is the one a
// zero-value struct gets wrong. MSDN, MIB_IPFORWARD_ROW2.NextHop: "If the route
// is to a local loopback address or an IP address on the local link, the next
// hop is unspecified (all zeros). For a local loopback route, this member should
// be an IPv4 address of 0.0.0.0 for an IPv4 route entry or an IPv6 address of
// 0::0 for an IPv6 route entry." Note what "all zeros" does NOT include: the
// ADDRESS FAMILY. CreateIpForwardEntry2 returns ERROR_INVALID_PARAMETER if "the
// NextHop member ... was not specified", and MSDN's Remarks require it be
// "initialized to a valid IPv4 or IPv6 address AND FAMILY". A left-zeroed
// SOCKADDR_INET has Family = AF_UNSPEC = 0 and is rejected; the family must be
// written even though the address is zero. This is precisely the mistake that
// compiles, looks right, and fails at runtime on someone else's machine.
//
// InterfaceLuid is left zero and InterfaceIndex carries the interface, which is
// the documented way round: "if the InterfaceLuid is specified, then this member
// is used ... If no value was set for the InterfaceLuid member (the values of
// this member was set to zero), then the InterfaceIndex member is next used."
// sysport identifies interfaces by NAME, and net.Interfaces gives back an index,
// not a LUID; going name -> LUID would need a second conversion with nothing to
// gain.
func routeRow(s sysport.RouteSpec, ifIndex uint32) (*windows.MibIpForwardRow2, error) {
	if s.Iface == "" {
		return nil, errRouteNeedsIface
	}
	dst := s.Dst.Masked()
	if !dst.IsValid() {
		return nil, fmt.Errorf("netstate: route destination %v is not a valid prefix", s.Dst)
	}
	dstAddr := dst.Addr()
	// An IPv4-mapped destination is REFUSED rather than quietly unmapped.
	// Unmapping the address without rebasing the prefix length is a silent
	// corruption: ::ffff:10.0.0.0/104 is 10.0.0.0/8, so an implementation that
	// calls Unmap() and keeps Bits() writes PrefixLength 104 into an AF_INET
	// row. netip.ParsePrefix accepts the 4-in-6 form and does not rebase it
	// either, so there is no length to infer here that the caller has not
	// already declined to state. tunfe unmaps every address it turns into a
	// prefix (hostPrefix), so nothing dpb installs reaches this.
	if dstAddr.Is4In6() {
		return nil, fmt.Errorf("netstate: route destination %s is an IPv4-mapped IPv6 prefix; "+
			"unmap it to an IPv4 prefix (and rebase its length) before installing it", dst)
	}

	row := &windows.MibIpForwardRow2{
		InterfaceIndex:    ifIndex,
		SitePrefixLength:  routeSitePrefixLength,
		ValidLifetime:     routeLifetimeInfinite,
		PreferredLifetime: routeLifetimeInfinite,
		Metric:            routeMetricOffset,
		// MSDN names MIB_IPPROTO_NETMGMT as the value identifying "route
		// information for IP routing set through network management ... or by
		// calls to the CreateIpForwardEntry2, DeleteIpForwardEntry2, or
		// SetIpForwardEntry2 functions" — i.e. this is the protocol value for
		// exactly what this call is.
		Protocol: windows.MIB_IPPROTO_NETMGMT,
		// Loopback, AutoconfigureAddress, Publish and Immortal stay false. We
		// are not creating a loopback route, the address is not autoconfigured,
		// dpb is not a router advertising anything, and immortality is not
		// needed to keep a route with an infinite ValidLifetime alive.
		//
		// Age and Origin stay zero because MSDN says they must: they "are
		// ignored when the CreateIpForwardEntry2 function is called. These
		// members are set by the network stack and cannot be set using the
		// CreateIpForwardEntry2 function."
	}
	setSockaddr(&row.DestinationPrefix.Prefix, dstAddr, 0)
	row.DestinationPrefix.PrefixLength = uint8(dst.Bits())

	nextHop := unspecifiedLike(dstAddr)
	if s.Gw.IsValid() {
		gw := s.Gw.Unmap()
		if gw.Is4() != dstAddr.Is4() {
			return nil, fmt.Errorf(
				"netstate: route %s has a next hop (%s) of the wrong address family; "+
					"a SOCKADDR_INET NextHop must match the DestinationPrefix family", dst, s.Gw)
		}
		nextHop = gw
	}
	// A link-local next hop is only meaningful together with the interface it
	// is on, and that interface is the one the route is being installed on —
	// there is no other candidate. The zone STRING that may be riding on s.Gw
	// (scdarwin's reader attaches interface names) is deliberately ignored:
	// SOCKADDR_IN6.sin6_scope_id is a numeric index, and the index we have is
	// the one the caller asked for.
	var scopeID uint32
	if nextHop.Is6() && (nextHop.IsLinkLocalUnicast() || nextHop.IsLinkLocalMulticast()) {
		scopeID = ifIndex
	}
	setSockaddr(&row.NextHop, nextHop, scopeID)
	return row, nil
}

// unspecifiedLike returns the all-zeros address of like's family: 0.0.0.0 for
// IPv4, :: for IPv6. It exists so the interface-route case writes a next hop
// with the right FAMILY and a zero address, which is what MSDN asks for and
// what a zero-valued struct does not give.
func unspecifiedLike(like netip.Addr) netip.Addr {
	if like.Is4() {
		return netip.AddrFrom4([4]byte{})
	}
	return netip.AddrFrom16([16]byte{})
}

// setSockaddr writes addr into a SOCKADDR_INET union, zeroing it first so that
// no byte of a previous family's layout survives underneath the new one.
//
// The unsafe conversion is the one x/sys/windows' own doc comment prescribes:
// "A [*RawSockaddrInet] may be converted to a [*RawSockaddrInet4] or
// [*RawSockaddrInet6] using unsafe, depending on the address family." All three
// layouts come from x/sys and none is redeclared here.
//
// Port stays zero: SOCKADDR_INET carries one because it is a socket address
// type, but a routing table entry has no port and the field is not part of what
// CreateIpForwardEntry2 or DeleteIpForwardEntry2 match on.
func setSockaddr(sa *windows.RawSockaddrInet, addr netip.Addr, scopeID uint32) {
	*sa = windows.RawSockaddrInet{}
	if addr.Is4() {
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
		p.Family = windows.AF_INET
		p.Addr = addr.As4()
		return
	}
	p := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
	p.Family = windows.AF_INET6
	p.Addr = addr.As16()
	p.Scope_id = scopeID
}
