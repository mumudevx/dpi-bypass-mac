package resolve

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// AAAAMode is the IPv6 answer policy.
type AAAAMode uint8

const (
	// AAAAAuto suppresses AAAA only on positive evidence. See aaaaPolicy.allow.
	AAAAAuto AAAAMode = iota
	AAAAAllow
	AAAASuppress // NOERROR + empty answer + SOA; never NXDOMAIN
)

func (m AAAAMode) String() string {
	switch m {
	case AAAAAllow:
		return "allow"
	case AAAASuppress:
		return "suppress"
	default:
		return "auto"
	}
}

// nat64Probe is the RFC 7050 well-known name. An AAAA answer for it can only
// have been synthesised by a DNS64 server, because the real zone has A records
// and no AAAA.
const nat64Probe = "ipv4only.arpa."

// nat64TTL is how long a NAT64 determination is trusted. Short enough that
// moving from a dual-stack office to a 464XLAT phone is noticed within a
// coffee break, long enough that it is not one extra query per name.
const nat64TTL = 10 * time.Minute

// wellKnownV4 are the addresses RFC 7050 §3 says ipv4only.arpa resolves to. A
// DNS64 server embeds one of them in the AAAA it synthesises, so finding the
// four bytes inside an answer both proves DNS64 and locates the prefix.
var wellKnownV4 = [][4]byte{
	{192, 0, 0, 170},
	{192, 0, 0, 171},
}

// nat64PrefixLens are the six prefix lengths RFC 6052 §2.2 permits.
var nat64PrefixLens = []int{32, 40, 48, 56, 64, 96}

// NAT64 is the outcome of a DNS64 probe.
type NAT64 struct {
	Detected bool
	Prefixes []netip.Prefix
	Detail   string
}

// aaaaPolicy decides whether AAAA answers may be returned.
type aaaaPolicy struct {
	mode   AAAAMode
	v4Path func() bool
	nat64  func(context.Context) NAT64

	mu         sync.Mutex
	v6Poisoned bool
	reason     string
}

// noteV6Poison records that an IPv6 answer on this network was a censorship
// sinkhole. It is the positive evidence AAAAAuto waits for.
func (p *aaaaPolicy) noteV6Poison(detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.v6Poisoned = true
	p.reason = detail
}

func (p *aaaaPolicy) v6PoisonSeen() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.v6Poisoned, p.reason
}

// allow reports whether AAAA answers may be returned, and why not when they may
// not.
//
// AAAAAuto suppresses only when all three of the following hold:
//
//  1. An IPv6 answer on this network has already been caught as a sinkhole.
//     DOSSIER GT19 registers 2a01:358:4014:a00::/64 to BTK, so a poisoned AAAA
//     is a real hazard here — but it is a hazard we can *observe* rather than
//     assume, and assuming it is what turns a laptop on a clean network into a
//     laptop with half its address families amputated.
//  2. A verified IPv4 path exists. Suppressing AAAA is only safe if there is
//     something left to connect with.
//  3. No NAT64/DNS64 was detected. On a 464XLAT carrier the AAAA *is* the
//     connectivity; suppressing it is a total outage, which the plan's shipped
//     defaults call out explicitly.
//
// The plan's one-line comment on AAAAAuto reads "allow only with a verified v4
// path and no NAT64", which taken literally would suppress AAAA on every
// v6-only network — the exact outage the same document forbids two pages later
// ("blanket AAAA suppression on a 464XLAT carrier is a total outage, so
// suppression is gated on positive evidence and NAT64 detection"). This
// implementation follows the gating requirement, because that is the reading
// under which both sentences are true and under which a user on an unmeasured
// Turkish mobile network still has working internet.
func (p *aaaaPolicy) allow(ctx context.Context) (bool, string) {
	switch p.mode {
	case AAAAAllow:
		return true, ""
	case AAAASuppress:
		return false, "ipv6 = suppress"
	}
	poisoned, why := p.v6PoisonSeen()
	if !poisoned {
		return true, ""
	}
	if p.v4Path == nil || !p.v4Path() {
		return true, ""
	}
	if p.nat64 != nil {
		if n := p.nat64(ctx); n.Detected {
			return true, ""
		}
	}
	return false, "ipv6 = auto and " + why
}

// hasGlobalIPv4 reports whether any interface carries a routable IPv4 address.
// It reads interface state; it resolves nothing.
func hasGlobalIPv4() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// detectNAT64 asks the chain for the RFC 7050 well-known name and reports
// whether the answer was synthesised.
//
// It queries through exchangeDirect, bypassing the AAAA policy: asking the AAAA
// policy whether we may ask the question the AAAA policy depends on is a cycle,
// and a suppressed probe would report "no NAT64" on precisely the networks
// where NAT64 is the only thing working.
func (c *Chain) detectNAT64(ctx context.Context) NAT64 {
	q, err := NewQuery(nat64Probe, dns.TypeAAAA)
	if err != nil {
		return NAT64{Detail: "could not build the ipv4only.arpa probe: " + err.Error()}
	}
	ans, err := c.exchangeDirect(ctx, q)
	if err != nil {
		return NAT64{Detail: "ipv4only.arpa probe failed: " + err.Error()}
	}
	var prefixes []netip.Prefix
	for _, a := range AnswerAddrs(ans) {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		if p, ok := nat64Prefix(a); ok {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) == 0 {
		return NAT64{Detail: "ipv4only.arpa returned no synthesised AAAA"}
	}
	return NAT64{Detected: true, Prefixes: prefixes, Detail: "DNS64 synthesis observed for ipv4only.arpa"}
}

// nat64Prefix locates the well-known IPv4 address inside a synthesised AAAA and
// returns the NAT64 prefix that produced it. Every legal prefix length is tried
// because the length is the carrier's choice, not ours.
func nat64Prefix(a netip.Addr) (netip.Prefix, bool) {
	b := a.As16()
	for _, bits := range nat64PrefixLens {
		got, ok := embeddedV4(b, bits)
		if !ok {
			continue
		}
		for _, want := range wellKnownV4 {
			if got == want {
				p, err := a.Prefix(bits)
				if err != nil {
					return netip.Prefix{}, false
				}
				return p, true
			}
		}
	}
	return netip.Prefix{}, false
}

// embeddedV4 extracts the IPv4 address embedded at the given prefix length per
// RFC 6052 §2.2. Bits 64-71 (byte 8) are the reserved u-octet and are excluded
// from the address, which is why the four bytes are not contiguous for every
// length; reading them contiguously would silently mis-detect a /48 as a /40.
func embeddedV4(b [16]byte, bits int) ([4]byte, bool) {
	// For every length except /32 and /96 the u-octet must be zero, otherwise
	// this is not an RFC 6052 address at all.
	if bits != 32 && bits != 96 && b[8] != 0 {
		return [4]byte{}, false
	}
	switch bits {
	case 32:
		return [4]byte{b[4], b[5], b[6], b[7]}, true
	case 40:
		return [4]byte{b[5], b[6], b[7], b[9]}, true
	case 48:
		return [4]byte{b[6], b[7], b[9], b[10]}, true
	case 56:
		return [4]byte{b[7], b[9], b[10], b[11]}, true
	case 64:
		return [4]byte{b[9], b[10], b[11], b[12]}, true
	case 96:
		return [4]byte{b[12], b[13], b[14], b[15]}, true
	default:
		return [4]byte{}, false
	}
}
