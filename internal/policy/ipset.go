package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// IPSet matches an address against prefix rules. It exists because a flow can
// arrive with no name at all — a TUN packet the ReverseMap could not name, a
// SOCKS5 request carrying ATYP=IPv4 — and those flows still need a verdict.
//
// It is immutable once built and safe for concurrent use.
type IPSet struct {
	entries []ipEntry
}

type ipEntry struct {
	prefix netip.Prefix
	rule   Rule
}

// NewIPSet compiles address rules. A pattern may be a prefix ("10.0.0.0/8") or
// a bare address, which is treated as a host route.
func NewIPSet(rules []Rule) (*IPSet, error) {
	s := &IPSet{}
	for _, r := range rules {
		p, err := ParsePrefix(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q from %s: %w", r.Pattern, r.Where(), err)
		}
		s.entries = append(s.entries, ipEntry{prefix: p, rule: r})
	}
	s.sort()
	return s, nil
}

// ParsePrefix accepts a CIDR or a bare address and returns the canonical,
// masked prefix. A bare address becomes a /32 or /128 host route.
func ParsePrefix(s string) (netip.Prefix, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return netip.Prefix{}, fmt.Errorf("empty address pattern")
	}
	if p, err := netip.ParsePrefix(t); err == nil {
		// Masking matters: 10.1.2.3/8 and 10.0.0.0/8 must behave identically,
		// and Prefix.Contains reports false for an unmasked prefix.
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(t)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an address or CIDR")
	}
	addr = canonAddr(addr)
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// sort puts longer (more specific) prefixes first so Match returns
// most-specific-first, the order the Engine relies on to pick an effective
// rule. Equal-length prefixes keep input order.
func (s *IPSet) sort() {
	sort.SliceStable(s.entries, func(i, j int) bool {
		return s.entries[i].prefix.Bits() > s.entries[j].prefix.Bits()
	})
}

// Match returns every rule covering addr, most specific first. A nil IPSet
// matches nothing.
func (s *IPSet) Match(addr netip.Addr) []Rule {
	if s == nil || len(s.entries) == 0 || !addr.IsValid() {
		return nil
	}
	a := canonAddr(addr)
	var out []Rule
	for _, e := range s.entries {
		// canonAddr is load-bearing twice over: the 4-in-6 unmap is what makes
		// ::ffff:10.0.0.1 hit the RFC1918 rule, and dropping the zone is what
		// makes fe80::1%en0 hit the link-local rule at all — netip.Prefix
		// strips zones, so Contains reports false for any zoned address.
		if e.prefix.Contains(a) {
			out = append(out, e.rule)
		}
	}
	return out
}

// Contains reports whether any rule covers addr.
func (s *IPSet) Contains(addr netip.Addr) bool {
	return len(s.Match(addr)) > 0
}

// Len reports how many prefixes the set holds.
func (s *IPSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// WithBogons returns a set containing s plus the compiled-in bogon table. It
// is safe on a nil receiver, and it never mutates s.
//
// The Engine calls this on construction and on every reload so that a rule
// file which forgets RFC1918 — or a reload that drops it — can still never
// cause dpb to buffer and desync a flow to the user's own router.
func (s *IPSet) WithBogons() *IPSet {
	out := &IPSet{}
	if s != nil {
		out.entries = append(out.entries, s.entries...)
	}
	for _, p := range bogonPrefixes {
		out.entries = append(out.entries, ipEntry{
			prefix: p,
			rule: Rule{
				Pattern: p.String(),
				Class:   ScopeBypass,
				From:    FromCompiledIn,
			},
		})
	}
	out.sort()
	return out
}

// bogonPrefixes are the addresses that are never a censored destination on the
// public internet, so desyncing a flow to one can only break something: the
// user's router, a corporate intranet, a loopback service, mDNS. They are a
// hard veto rather than a heuristic.
var bogonPrefixes = mustPrefixes(
	// RFC 1122 "this network", and the broadcast address.
	"0.0.0.0/8",
	"255.255.255.255/32",
	// Loopback.
	"127.0.0.0/8",
	"::1/128",
	// RFC 1918 private use.
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// RFC 6598 carrier-grade NAT — a mobile handset's own address range.
	"100.64.0.0/10",
	// Link-local, including the macOS self-assigned range and IPv6 fe80::/10.
	"169.254.0.0/16",
	"fe80::/10",
	// RFC 6890 IETF protocol assignments and the DS-Lite range.
	"192.0.0.0/24",
	// RFC 2544 benchmarking. Named here because other tools allocate fake IPs
	// out of 198.18.0.0/15; dpb has no fake-IP layer, but a flow to that range
	// is still not a censorship target.
	"198.18.0.0/15",
	// Multicast and the v6 equivalent.
	"224.0.0.0/4",
	"ff00::/8",
	// RFC 4193 unique local addresses.
	"fc00::/7",
	// RFC 6666 discard-only.
	"100::/64",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic("policy: bad compiled-in bogon prefix " + s + ": " + err.Error())
		}
		out = append(out, p.Masked())
	}
	return out
}

// canonAddr is the single canonical form for every address key and every
// prefix test in this package: 4-in-6 unmapped, and with any IPv6 zone
// stripped.
func canonAddr(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// BogonPrefixes returns a copy of the compiled-in table, for `dpb scope list`
// and for config, which must not restate it.
func BogonPrefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), bogonPrefixes...)
}

// IsBogon reports whether addr is in the compiled-in table.
func IsBogon(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := canonAddr(addr)
	for _, p := range bogonPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
