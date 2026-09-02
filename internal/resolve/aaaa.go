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
	v6Path func() bool
	v6Host func() bool
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

// v6Protected reports whether some front end is actually carrying IPv6 for
// this machine right now. A nil predicate means nobody claimed it, which reads
// as NOT protected: forgetting to wire the gate must fail closed.
func (p *aaaaPolicy) v6Protected() bool {
	return p.v6Path != nil && p.v6Path()
}

// allow reports whether AAAA answers may be returned to DPB ITSELF — the
// addresses this process is about to dial — and why not when they may not.
//
// Our own dials are protected in both families by construction: whatever we
// dial, we dial through the ladder. But PROTECTED is not REACHABLE, and that
// distinction cost a real outage: on a machine with no global IPv6 address,
// www.turkiye.gov.tr resolved to both families, the A lookup lost one race, the
// AAAA-only answer was cached, and eight consecutive requests through the proxy
// died instantly with "connect: no route to host" while the site loaded fine
// outside dpb. So an address family this host cannot reach is withheld from our
// own dials too, under the same escapes as every other suppression.
func (p *aaaaPolicy) allow(ctx context.Context) (bool, string) {
	return p.decide(ctx, false)
}

// allowServed is the same decision for an answer we are about to hand to
// ANOTHER PROCESS on this machine, which is the fail-closed one.
//
// A local application does what it likes with an AAAA record: it opens its own
// socket to that address, and whether that socket is protected depends entirely
// on whether this run is capturing IPv6. When it is not, answering AAAA hands
// the application an address for traffic we cannot touch, on a line where
// DOSSIER GT19 records the IPv6 sinkhole 2a01:358:4014:a00::3 as registered to
// BTK itself. That is the silent fail-open this policy exists to close, and it
// is why the "is IPv6 protected" predicate defaults to false.
func (p *aaaaPolicy) allowServed(ctx context.Context) (bool, string) {
	return p.decide(ctx, true)
}

// decide is the shared rule. served says the answer is leaving this process.
//
// AAAAAuto suppresses only when a reason to suppress is present AND both
// escapes are absent:
//
//  1. A reason: either an IPv6 answer on this network was already caught as a
//     sinkhole, or (for a served answer) nothing is carrying IPv6 on this run.
//  2. A verified IPv4 path exists. Suppressing AAAA is only safe if there is
//     something left to connect with; without one it is a total outage.
//  3. No NAT64/DNS64 was detected. On a 464XLAT carrier the AAAA *is* the
//     connectivity, and suppressing it is again a total outage — the plan's
//     shipped defaults call this out explicitly.
//
// The plan's one-line comment on AAAAAuto reads "allow only with a verified v4
// path and no NAT64", which taken literally would suppress AAAA on every
// v6-only network — the exact outage the same document forbids two pages later
// ("blanket AAAA suppression on a 464XLAT carrier is a total outage, so
// suppression is gated on positive evidence and NAT64 detection"). This
// implementation follows the gating requirement, because that is the reading
// under which both sentences are true and under which a user on an unmeasured
// Turkish mobile network still has working internet.
func (p *aaaaPolicy) decide(ctx context.Context, served bool) (bool, string) {
	switch p.mode {
	case AAAAAllow:
		return true, ""
	case AAAASuppress:
		return false, "ipv6 = suppress"
	}
	poisoned, why := p.v6PoisonSeen()
	unprotected := served && !p.v6Protected()
	unreachable := !served && !p.v6Reachable()
	if !poisoned && !unprotected && !unreachable {
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
	if unprotected {
		return false, "ipv6 = auto and nothing is carrying IPv6 on this run, so an AAAA answer " +
			"would hand an application an address dpb cannot protect"
	}
	if unreachable {
		return false, "ipv6 = auto and this host has no global IPv6 address, so dialling an " +
			"AAAA answer can only fail with no route to host"
	}
	return false, "ipv6 = auto and " + why
}

// v6Reachable reports whether this host could dial an IPv6 address at all.
// A nil predicate reads as reachable: this gate withholds addresses, so an
// unwired predicate must not be the thing that suppresses a whole family.
func (p *aaaaPolicy) v6Reachable() bool {
	// A run that is carrying IPv6 has, by definition, a path for it: the utun
	// holds the address and the capture routes are installed. So protection
	// implies reachability, and only an unprotected run has to ask the host.
	if p.v6Protected() {
		return true
	}
	if p.v6Host == nil {
		return true
	}
	return p.v6Host()
}

// hasGlobalIPv6 is v6Reachable's default: a routable IPv6 address on some
// interface. A link-local address is not one — every macOS interface has one
// and none of them can reach the internet. Under --tun the utun's ULA counts,
// which is correct: that run is carrying IPv6 itself.
func hasGlobalIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
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
		if ip.Is6() && !ip.Is4In6() && !ip.IsLoopback() &&
			!ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			return true
		}
	}
	return false
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
