package netstate

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// RouteEntry is one kernel routing table entry, reduced to the fields we
// actually make decisions on.
type RouteEntry struct {
	Dst     netip.Prefix
	Gateway netip.Addr
	Iface   string
	Index   int
	// Scoped is true for a route carrying RTF_IFSCOPE — macOS's per-interface
	// scoping. A VPN's scoped default lives here, and recognising it is what
	// stops us from deleting someone's VPN on Ctrl-C.
	Scoped bool
}

func (r RouteEntry) String() string {
	gw := "-"
	if r.Gateway.IsValid() {
		gw = r.Gateway.String()
	}
	s := fmt.Sprintf("%s via %s dev %s(%d)", r.Dst, gw, r.Iface, r.Index)
	if r.Scoped {
		s += " scoped"
	}
	return s
}

// RIBReader reads the kernel routing table directly through an AF_ROUTE socket.
// It is the independent verifier for every route mutation: route(8) writes,
// this reads, and the two never share a code path.
//
// Verified openable unprivileged on this machine: FetchRIB returned 19808 bytes
// / 121 messages as uid 501.
type RIBReader interface {
	Routes() ([]RouteEntry, error)
	Default() (RouteEntry, bool, error)
	ScopedDefault(iface string) (RouteEntry, bool, error)
	Exists(dst netip.Prefix, iface string) (bool, error)
}

// NewRIB returns the kernel-backed RIBReader.
func NewRIB() RIBReader { return &kernelRIB{} }

type kernelRIB struct {
	mu    sync.Mutex
	names map[int]string
	// namesAt bounds how stale the index->name map may be. Interface indices are
	// stable for the life of a device, but a utun appearing mid-run must be
	// visible to the very next Verify, so the cache is short-lived rather than
	// permanent.
	namesAt time.Time
}

const ifaceCacheTTL = 2 * time.Second

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

func (k *kernelRIB) Routes() ([]RouteEntry, error) {
	names, err := k.ifaceNames()
	if err != nil {
		return nil, err
	}
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("netstate: fetch routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("netstate: parse routing table: %w", err)
	}
	out := make([]RouteEntry, 0, len(msgs))
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		e, ok := routeEntryFrom(rm, names)
		if !ok {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// routeEntryFrom converts one RTM message. It returns ok=false for entries we
// cannot express as a prefix (link-layer/ARP cache entries, malformed
// addresses), which are never the subject of a mutation we make.
func routeEntryFrom(rm *route.RouteMessage, names map[int]string) (RouteEntry, bool) {
	if rm.Flags&unix.RTF_UP == 0 {
		return RouteEntry{}, false
	}
	if len(rm.Addrs) <= 1 {
		return RouteEntry{}, false
	}
	dst, ok := addrOf(rm.Addrs[0])
	if !ok {
		return RouteEntry{}, false
	}
	bits := dst.BitLen()
	if rm.Flags&unix.RTF_HOST == 0 {
		if len(rm.Addrs) > 2 {
			if n, ok := maskBits(rm.Addrs[2], dst.BitLen()); ok {
				bits = n
			}
		}
	}
	pfx := netip.PrefixFrom(dst, bits)
	if !pfx.IsValid() {
		return RouteEntry{}, false
	}
	e := RouteEntry{
		Dst:    pfx.Masked(),
		Index:  rm.Index,
		Iface:  names[rm.Index],
		Scoped: rm.Flags&unix.RTF_IFSCOPE != 0,
	}
	// A gateway is either a next-hop address or a link address, the latter
	// meaning "route add -interface". Only the former is a Gateway to us.
	switch ga := rm.Addrs[1].(type) {
	case *route.LinkAddr:
		if e.Iface == "" {
			e.Iface = ga.Name
		}
		if e.Index == 0 {
			e.Index = ga.Index
		}
	default:
		if gw, ok := addrOf(rm.Addrs[1]); ok && !gw.IsUnspecified() {
			e.Gateway = gw
		}
	}
	return e, true
}

func addrOf(a route.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(v.IP), true
	case *route.Inet6Addr:
		ip := netip.AddrFrom16(v.IP)
		// Link-local next hops carry a zone id; keeping it makes fe80::%utun0
		// distinguishable from fe80::%utun1, which matters when several tunnels
		// each install a default.
		if v.ZoneID != 0 && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			ip = ip.WithZone(zoneName(v.ZoneID))
		}
		return ip, true
	default:
		return netip.Addr{}, false
	}
}

func zoneName(idx int) string {
	if in, err := net.InterfaceByIndex(idx); err == nil {
		return in.Name
	}
	return fmt.Sprintf("%d", idx)
}

// maskBits converts a netmask address into a prefix length. The kernel encodes
// netmasks in a truncated form; x/net/route has already zero-extended it, so a
// plain leading-ones count is correct.
func maskBits(a route.Addr, want int) (int, bool) {
	var b []byte
	switch v := a.(type) {
	case *route.Inet4Addr:
		b = v.IP[:]
	case *route.Inet6Addr:
		b = v.IP[:]
	default:
		return 0, false
	}
	if len(b)*8 != want {
		// A v4 destination with a v6-shaped mask (or the reverse) is a message we
		// do not understand; refusing it beats inventing a prefix length.
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c == 0xff {
			n += 8
			continue
		}
		for c&0x80 != 0 {
			n++
			c <<= 1
		}
		break
	}
	return n, true
}

func (k *kernelRIB) Default() (RouteEntry, bool, error) {
	rs, err := k.Routes()
	if err != nil {
		return RouteEntry{}, false, err
	}
	return pickDefault(rs, "")
}

func (k *kernelRIB) ScopedDefault(iface string) (RouteEntry, bool, error) {
	rs, err := k.Routes()
	if err != nil {
		return RouteEntry{}, false, err
	}
	return pickDefault(rs, iface)
}

// pickDefault finds the unscoped default when iface is empty, or the
// interface-scoped default for iface when it is not. IPv4 wins over IPv6
// because callers use it to identify the uplink, and on a dual-stack macOS box
// the v4 default is the one that names the physical service.
func pickDefault(rs []RouteEntry, iface string) (RouteEntry, bool, error) {
	var v6 RouteEntry
	var haveV6 bool
	for _, r := range rs {
		if r.Dst.Bits() != 0 {
			continue
		}
		if iface == "" {
			if r.Scoped {
				continue
			}
		} else if !r.Scoped || r.Iface != iface {
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

func routeExists(rs []RouteEntry, dst netip.Prefix, iface string) bool {
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

// interfaceLister is a seam so Verify paths that read net.Interfaces() can be
// driven by a fake system in tests. It is deliberately not part of Env: every
// production caller wants the real kernel.
var interfaceLister = net.Interfaces

// interfaceAddrser mirrors interfaceLister for per-interface addresses.
var interfaceAddrser = func(in *net.Interface) ([]net.Addr, error) { return in.Addrs() }
