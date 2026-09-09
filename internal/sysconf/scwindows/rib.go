//go:build windows

package scwindows

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// newKernelRIB returns the IP-Helper-backed RIBReader.
func newKernelRIB() sysport.RIBReader { return &kernelRIB{} }

type kernelRIB struct {
	mu    sync.Mutex
	names map[int]string
	// namesAt bounds how stale the index->name map may be, for the reason
	// scdarwin gives: interface indices are stable for the life of a device,
	// but a tunnel adapter appearing mid-run must be visible to the very next
	// Verify, so the cache is short-lived rather than permanent. Windows adds
	// a second reason — MSDN says of MIB_IPFORWARD_ROW2.InterfaceIndex that it
	// "may change when a network adapter is disabled and then enabled, or under
	// other circumstances, and should not be considered persistent."
	namesAt time.Time
}

const ifaceCacheTTL = 2 * time.Second

// interfaceLister is a seam so Verify paths that read net.Interfaces() can be
// driven by a fake system in tests, mirroring scdarwin. It is deliberately not
// part of Env: every production caller wants the real machine.
//
// net.Interfaces is implemented on Windows — verified by reading
// $GOROOT/src/net/interface_windows.go, where interfaceTable() calls
// GetAdaptersAddresses and fills Interface.Name from the adapter's
// FriendlyName. That check is not ceremony: Plan 2 found three Windows stdlib
// functions that compile, look right and always fail.
var interfaceLister = net.Interfaces

func (k *kernelRIB) ifaceNames() (map[int]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.names != nil && time.Since(k.namesAt) < ifaceCacheTTL {
		return k.names, nil
	}
	ifs, err := interfaceLister()
	if err != nil {
		return nil, fmt.Errorf("netstate: enumerate interfaces: %w", err)
	}
	m := make(map[int]string, len(ifs))
	for _, in := range ifs {
		m[in.Index] = in.Name
	}
	k.names, k.namesAt = m, time.Now()
	return m, nil
}

// Routes reads the whole IP routing table through GetIpForwardTable2.
//
// It asks for AF_UNSPEC, which MSDN defines as "returns the IP routing table
// containing both IPv4 and IPv6 entries" — one call rather than two, so a
// caller cannot observe a table where the v4 half was read before a network
// change and the v6 half after it.
func (k *kernelRIB) Routes() ([]sysport.RouteEntry, error) {
	names, err := k.ifaceNames()
	if err != nil {
		return nil, err
	}

	// MSDN, GetIpForwardTable2: "When these returned structures are no longer
	// required, free the memory by calling the FreeMibTable." The table is
	// unmanaged memory that the Go garbage collector will never touch, so the
	// free is deferred BEFORE the error is even examined — every path out of
	// this function, including the failure path and any future early return
	// added below, goes through it.
	//
	// The nil guard is not defensive noise: MSDN does not promise that Table is
	// left unset when the call fails, and it does not document FreeMibTable(NULL)
	// as a no-op either, so the only claim safe to make is about the pointer we
	// can see.
	var table *windows.MibIpForwardTable2
	tableErr := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table)
	defer func() {
		if table != nil {
			windows.FreeMibTable(unsafe.Pointer(table))
		}
	}()
	if tableErr != nil {
		// ERROR_NOT_FOUND ("No IP route entries as specified in the Family
		// parameter were found") is deliberately NOT translated into an empty
		// table. A machine dpb is running on always has routes, so an empty
		// answer here is a read that failed, and reading it as "no routes" would
		// let VerifyReverted report a clean teardown having deleted nothing.
		return nil, fmt.Errorf("netstate: read the routing table: %w", tableErr)
	}

	// Rows() is x/sys/windows' own accessor. Using it rather than walking the
	// array by hand is the point: MSDN warns that the table "may contain padding
	// for alignment between the NumEntries member and the first
	// MIB_IPFORWARD_ROW2 array entry" and "also ... between the
	// MIB_IPFORWARD_ROW2 array entries", and a hand-written walk is exactly
	// where that assumption goes wrong silently. The slice it returns aliases
	// the unmanaged table, so nothing derived from it may outlive this function
	// — every RouteEntry below copies the values it keeps.
	rows := table.Rows()
	out := make([]sysport.RouteEntry, 0, len(rows))
	for i := range rows {
		e, ok := routeEntryFrom(&rows[i], names)
		if !ok {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// routeEntryFrom converts one MIB_IPFORWARD_ROW2. It returns ok=false for rows
// whose destination is not an address family we can express as a netip.Prefix,
// which are never the subject of a mutation we make.
//
// # What Scoped means on Windows, and why
//
// RouteEntry.Scoped carries RTF_IFSCOPE on macOS, where it is part of a route's
// IDENTITY: netstate's matchRoute compares it, a scoped entry does not satisfy
// an unscoped request, and an unscoped entry does not satisfy a scoped one.
// Windows has no such flag, so the meaning has to be chosen, and the choice is
// constrained from both ends — the reader must report the same Scoped value the
// writer's rows will read back with, or every Verify fails.
//
// Here Scoped means: THIS ROW HAS A NEXT HOP. Equivalently, it is a gateway
// route rather than an on-link (interface) route.
//
// That is the only assignment consistent with matchRoute, which computes
// wantScoped as `gw.IsValid() && iface != ""`:
//
//   - RouteSpec{Dst, Gw valid, Iface set} — the scoped uplink default —
//     wants Scoped true, and route.go writes it with NextHop = Gw. True. ✓
//   - RouteSpec{Dst, Gw invalid, Iface set} — the capture routes —
//     wants Scoped false, and route.go writes NextHop = the unspecified address
//     of the destination's family, per MSDN's "If the route is to ... an IP
//     address on the local link, the next hop is unspecified (all zeros)".
//     False. ✓
//
// Note what this does NOT mean. On Windows every row is bound to an interface:
// MIB_IPFORWARD_ROW2 requires InterfaceLuid or InterfaceIndex, and
// CreateIpForwardEntry2 returns ERROR_INVALID_PARAMETER when "both ... were
// unspecified". So there is no unscoped/scoped distinction among gateway routes
// to report, and "Scoped" here is not describing a property the row possesses
// beyond having a next hop — it is the identity bit matchRoute compares, mapped
// onto the only observable difference Windows rows actually have.
//
// The third RouteSpec shape, {Gw valid, Iface empty}, is what this costs: it
// would want Scoped false while producing a row indistinguishable from the
// first shape. routeCtl.Add refuses it by name rather than installing a route
// that can never verify; see route.go.
func routeEntryFrom(row *windows.MibIpForwardRow2, names map[int]string) (sysport.RouteEntry, bool) {
	dst, ok := sockaddrAddr(&row.DestinationPrefix.Prefix)
	if !ok {
		return sysport.RouteEntry{}, false
	}
	pfx := netip.PrefixFrom(dst, int(row.DestinationPrefix.PrefixLength))
	if !pfx.IsValid() {
		// A PrefixLength wider than the family (MSDN calls 255 the conventional
		// "illegal value") is a row we do not understand; refusing it beats
		// inventing a prefix length.
		return sysport.RouteEntry{}, false
	}
	idx := int(row.InterfaceIndex)
	e := sysport.RouteEntry{
		Dst:   pfx.Masked(),
		Index: idx,
		Iface: names[idx],
	}
	// An unspecified next hop is not a gateway: MSDN says of NextHop that "if
	// the route is to a local loopback address or an IP address on the local
	// link, the next hop is unspecified (all zeros)". That is Windows' spelling
	// of macOS' link-address gateway, i.e. `route add -interface`, and scdarwin
	// declines to call that a Gateway for the same reason.
	if gw, ok := sockaddrAddr(&row.NextHop); ok && !gw.IsUnspecified() {
		// Link-local next hops carry a zone, which makes fe80::1%tun0
		// distinguishable from fe80::1%tun1 when several tunnels each install a
		// default. scdarwin attaches the same zone from the same source (the
		// row's own interface), and netstate's sameGateway strips it before
		// comparing, so this is for humans reading `dpb doctor`, not for
		// matching.
		if gw.Is6() && (gw.IsLinkLocalUnicast() || gw.IsLinkLocalMulticast()) {
			gw = gw.WithZone(zoneName(idx, names))
		}
		e.Gateway = gw
		e.Scoped = true
	}
	return e, true
}

// zoneName names the interface a link-local address is scoped to, falling back
// to the numeric index when the adapter is not in the name map — which happens
// for an interface that appeared between the cache refresh and this read.
func zoneName(idx int, names map[int]string) string {
	if n := names[idx]; n != "" {
		return n
	}
	return strconv.Itoa(idx)
}

// sockaddrAddr decodes a SOCKADDR_INET union.
//
// The union is read through the unsafe conversion x/sys/windows' own doc
// comment prescribes: "A [*RawSockaddrInet] may be converted to a
// [*RawSockaddrInet4] or [*RawSockaddrInet6] using unsafe, depending on the
// address family." Those three layouts come from x/sys and are not redeclared
// here, because a hand-copied layout is how a field offset goes silently wrong.
func sockaddrAddr(sa *windows.RawSockaddrInet) (netip.Addr, bool) {
	switch sa.Family {
	case windows.AF_INET:
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrFrom4(p.Addr), true
	case windows.AF_INET6:
		p := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
		return netip.AddrFrom16(p.Addr), true
	default:
		// AF_UNSPEC, and anything else, is a row whose destination or next hop
		// we cannot express.
		return netip.Addr{}, false
	}
}

func (k *kernelRIB) Default() (sysport.RouteEntry, bool, error) {
	rs, err := k.Routes()
	if err != nil {
		return sysport.RouteEntry{}, false, err
	}
	return pickDefault(rs, "")
}

func (k *kernelRIB) ScopedDefault(iface string) (sysport.RouteEntry, bool, error) {
	rs, err := k.Routes()
	if err != nil {
		return sysport.RouteEntry{}, false, err
	}
	return pickDefault(rs, iface)
}

// pickDefault finds the machine's default route when iface is empty, or the
// default route on iface when it is not. IPv4 wins over IPv6 for scdarwin's
// reason: callers use this to identify THE uplink, and on a dual-stack box the
// v4 default is the one that names the physical adapter.
//
// It deliberately does NOT filter on Scoped, and that is the one place this
// reader's shape departs from scdarwin's pickDefault. There, `iface == ""`
// means "the UNSCOPED default", because macOS keeps the system default and a
// VPN's per-interface default as two distinguishable entries. Windows keeps no
// such distinction: every default route has a next hop, so under this package's
// definition of Scoped every default route is Scoped, and carrying scdarwin's
// `if r.Scoped { continue }` across would make Default() return nothing at all
// on a perfectly normal machine.
//
// What it cannot do: rank several defaults. MSDN says the table "may contain
// multiple MIB_IPFORWARD_ROW2 entries with the Prefix and the PrefixLength ...
// set to zero ... when there are multiple network adapters installed", and the
// value that orders them is the sum of the row's Metric offset and the
// interface metric from MIB_IPINTERFACE_ROW — neither of which survives into
// RouteEntry. So this returns the first match and nothing more is claimed for
// it; a caller that needs the FIB's actual choice has to ask GetBestRoute2.
//
// facts.go deliberately does NOT: Facts.Uplink and dnsCtl.Live's own default-
// route read must name the SAME interface or a correctly configured adapter
// fails its DNS verify, and agreement between the two is worth more than an
// uplink that is independently more accurate. factsCtl.Collect writes that
// trade-off down in full.
func pickDefault(rs []sysport.RouteEntry, iface string) (sysport.RouteEntry, bool, error) {
	var v6 sysport.RouteEntry
	var haveV6 bool
	for _, r := range rs {
		if r.Dst.Bits() != 0 {
			continue
		}
		if iface != "" && r.Iface != iface {
			continue
		}
		if r.Dst.Addr().Is4() {
			return r, true, nil
		}
		if !haveV6 {
			v6, haveV6 = r, true
		}
	}
	return v6, haveV6, nil
}

func (k *kernelRIB) Exists(dst netip.Prefix, iface string) (bool, error) {
	rs, err := k.Routes()
	if err != nil {
		return false, err
	}
	return routeExists(rs, dst, iface), nil
}

func routeExists(rs []sysport.RouteEntry, dst netip.Prefix, iface string) bool {
	want := dst.Masked()
	for _, r := range rs {
		if r.Dst != want {
			continue
		}
		if iface == "" || r.Iface == iface {
			return true
		}
	}
	return false
}
