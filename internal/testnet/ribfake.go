package testnet

import (
	"net/netip"
	"sync"

	"github.com/mumudevx/dpb/internal/netstate"
)

// RIB is an in-memory netstate.RIBReader.
//
// It exists so route verification is testable in BOTH directions. The kernel
// reader can only be driven by mutating the machine's real routing table, which
// means the interesting cases — a route command that reported success and did
// nothing, a VPN's scoped default that must never be reverted — could not be
// tested at all. Here they are two lines of setup.
type RIB struct {
	mu     sync.Mutex
	routes []netstate.RouteEntry
	err    error
	reads  int
}

var _ netstate.RIBReader = (*RIB)(nil)

// NewRIB returns a RIB pre-seeded with routes.
func NewRIB(routes ...netstate.RouteEntry) *RIB {
	return &RIB{routes: append([]netstate.RouteEntry(nil), routes...)}
}

// SetErr makes every read fail, modelling an AF_ROUTE socket that cannot be
// opened. Verification must surface this rather than treating an unreadable RIB
// as "the route is absent".
func (r *RIB) SetErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

// Set replaces the table.
func (r *RIB) Set(routes ...netstate.RouteEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = append([]netstate.RouteEntry(nil), routes...)
}

// Add appends a route, replacing any entry with the same destination and
// interface, the way the kernel does.
func (r *RIB) Add(e netstate.RouteEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Dst = e.Dst.Masked()
	for i, existing := range r.routes {
		if existing.Dst == e.Dst && existing.Iface == e.Iface {
			r.routes[i] = e
			return
		}
	}
	r.routes = append(r.routes, e)
}

// Remove deletes the matching route and reports whether anything was removed.
// An empty iface matches any interface.
func (r *RIB) Remove(dst netip.Prefix, iface string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := dst.Masked()
	out := r.routes[:0]
	removed := false
	for _, e := range r.routes {
		if e.Dst == want && (iface == "" || e.Iface == iface) {
			removed = true
			continue
		}
		out = append(out, e)
	}
	r.routes = out
	return removed
}

// Reads is the number of times the table has been read. A Verify that never
// reads the RIB is a Verify that trusts route(8), which is the defect this whole
// package exists to prevent.
func (r *RIB) Reads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads
}

// Routes implements netstate.RIBReader.
func (r *RIB) Routes() ([]netstate.RouteEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	if r.err != nil {
		return nil, r.err
	}
	return append([]netstate.RouteEntry(nil), r.routes...), nil
}

// Default implements netstate.RIBReader.
func (r *RIB) Default() (netstate.RouteEntry, bool, error) {
	rs, err := r.Routes()
	if err != nil {
		return netstate.RouteEntry{}, false, err
	}
	return pickDefault(rs, "")
}

// ScopedDefault implements netstate.RIBReader.
func (r *RIB) ScopedDefault(iface string) (netstate.RouteEntry, bool, error) {
	rs, err := r.Routes()
	if err != nil {
		return netstate.RouteEntry{}, false, err
	}
	return pickDefault(rs, iface)
}

// Exists implements netstate.RIBReader.
func (r *RIB) Exists(dst netip.Prefix, iface string) (bool, error) {
	rs, err := r.Routes()
	if err != nil {
		return false, err
	}
	want := dst.Masked()
	for _, e := range rs {
		if e.Dst == want && (iface == "" || e.Iface == iface) {
			return true, nil
		}
	}
	return false, nil
}

// pickDefault mirrors the kernel reader: the unscoped default when iface is
// empty, the interface-scoped one otherwise, IPv4 winning over IPv6 because
// callers use the answer to name the physical uplink.
func pickDefault(rs []netstate.RouteEntry, iface string) (netstate.RouteEntry, bool, error) {
	var v6 netstate.RouteEntry
	var haveV6 bool
	for _, e := range rs {
		if e.Dst.Bits() != 0 {
			continue
		}
		if iface == "" {
			if e.Scoped {
				continue
			}
		} else if !e.Scoped || e.Iface != iface {
			continue
		}
		if e.Dst.Addr().Is4() {
			return e, true, nil
		}
		if !haveV6 {
			v6, haveV6 = e, true
		}
	}
	return v6, haveV6, nil
}

// Default4 builds an unscoped IPv4 default route via gw on iface.
func Default4(gw, iface string, index int) netstate.RouteEntry {
	return netstate.RouteEntry{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: netip.MustParseAddr(gw),
		Iface:   iface,
		Index:   index,
	}
}

// Default6 builds an unscoped IPv6 default route via gw on iface.
func Default6(gw, iface string, index int) netstate.RouteEntry {
	return netstate.RouteEntry{
		Dst:     netip.MustParsePrefix("::/0"),
		Gateway: netip.MustParseAddr(gw),
		Iface:   iface,
		Index:   index,
	}
}

// ScopedDefault4 builds an interface-scoped IPv4 default — the shape a VPN
// installs, and the one Revert must leave alone because we did not create it.
func ScopedDefault4(gw, iface string, index int) netstate.RouteEntry {
	e := Default4(gw, iface, index)
	e.Scoped = true
	return e
}

// Host4 builds a /32 host route, the shape used to pin an upstream to the
// physical uplink while a tunnel owns the default.
func Host4(dst, gw, iface string, index int) netstate.RouteEntry {
	return netstate.RouteEntry{
		Dst:     netip.PrefixFrom(netip.MustParseAddr(dst), 32),
		Gateway: netip.MustParseAddr(gw),
		Iface:   iface,
		Index:   index,
	}
}
