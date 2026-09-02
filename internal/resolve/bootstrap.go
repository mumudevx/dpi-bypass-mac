package resolve

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Endpoint is one rung of the DNS chain expressed as data, so the shipped
// default, a tuned profile and `dpb dns check` all describe a resolver the same
// way.
type Endpoint struct {
	Label     string
	Transport string       // "doh" | "dot" | "udp" | "udp-alt"
	Target    string       // DoH URL, or a literal ip:port for dot/udp
	Bootstrap []netip.Addr // DoH only: the addresses the URL's host is dialled at
}

// DefaultEndpoints is the shipped chain, in order.
//
// Every address here is hardcoded on purpose. The update channel for this list
// is itself censorable, so the binary must be able to resolve the first name it
// ever needs without asking anything it does not already trust. The order is
// the one in the plan's Turkey profile:
//
//  1. DoH cloudflare-dns.com — ~26k OONI measurements with no confirmed block
//     (DOSSIER GT4), corroborated live.
//  2. DoH dns.google — GT4.
//  3. DoT 9.9.9.9:853 — GT4 ("DoT/853 connects").
//  4. UDP 77.88.8.8:1253 — MEASUREMENTS.md §2: `dig -p 1253 @77.88.8.8
//     discord.com` returns 162.159.128.233, 162.159.136.232 while port 53 for
//     the same name times out.
//  5. UDP 9.9.9.9:9953 — MEASUREMENTS.md §2, same result.
//
// Plain UDP on port 53 is deliberately absent: §2 measures it as per-QNAME
// dropped for exactly the names this tool exists to reach.
func DefaultEndpoints() []Endpoint {
	return []Endpoint{
		{
			Label:     "doh-cloudflare",
			Transport: "doh",
			Target:    "https://cloudflare-dns.com/dns-query",
			Bootstrap: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("1.0.0.1"),
			},
		},
		{
			Label:     "doh-google",
			Transport: "doh",
			Target:    "https://dns.google/dns-query",
			Bootstrap: []netip.Addr{
				netip.MustParseAddr("8.8.8.8"),
				netip.MustParseAddr("8.8.4.4"),
			},
		},
		{Label: "dot-quad9", Transport: "dot", Target: "9.9.9.9:853"},
		{Label: "udp-yandex-1253", Transport: "udp-alt", Target: "77.88.8.8:1253"},
		{Label: "udp-quad9-9953", Transport: "udp-alt", Target: "9.9.9.9:9953"},
	}
}

// New builds the resolver an Endpoint describes. dial is the uplink-bound,
// desyncing dial path used for DoH and DoT so the resolver's own ClientHello
// gets the same protection as everything else; ud is the dialer used for
// plaintext UDP. Either may be nil, in which case a plain dialer is used.
func (e Endpoint) New(dial DialFunc, ud *net.Dialer) (Resolver, error) {
	switch e.Transport {
	case "doh":
		r, err := NewDoH(e.Target, e.Bootstrap, dial)
		if err != nil {
			return nil, err
		}
		return relabel(r, e.Label), nil
	case "dot":
		r, err := NewDoT(e.Target, dial)
		if err != nil {
			return nil, err
		}
		return relabel(r, e.Label), nil
	case "udp", "udp-alt":
		return NewUDP(e.Label, e.Target, ud)
	default:
		// A transport that names a stream network is not merely unknown, it is
		// forbidden, and it must say so with the measurement attached.
		// ForbidTCP is the lever a configuration layer trips: a profile
		// carrying `transport = "tcp"` (or an `allow_tcp53 = true` that lowers
		// to one) fails here rather than becoming a silent hole in the chain.
		// This is the only call site where the argument is data rather than a
		// compile-time constant, which is the whole point of the lever.
		if strings.HasPrefix(e.Transport, streamNetwork) {
			if err := ForbidTCP(e.Transport); err != nil {
				return nil, fmt.Errorf("resolve: endpoint %q: %w", e.Label, err)
			}
		}
		return nil, fmt.Errorf("resolve: endpoint %q has unknown transport %q", e.Label, e.Transport)
	}
}

// DefaultResolvers builds DefaultEndpoints. A single bad endpoint is fatal:
// silently shipping a shorter chain than the one that was measured is how a
// user ends up on a transport that MEASUREMENTS.md §2 already ruled out.
func DefaultResolvers(dial DialFunc, ud *net.Dialer) ([]Resolver, error) {
	eps := DefaultEndpoints()
	out := make([]Resolver, 0, len(eps))
	for _, e := range eps {
		r, err := e.New(dial, ud)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// labelled overrides a resolver's own label with the one from configuration so
// log lines, `dpb dns check` rows and tuned-profile entries agree.
type labelled struct {
	Resolver
	label string
}

func (l labelled) Label() string { return l.label }

func relabel(r Resolver, label string) Resolver {
	if label == "" {
		return r
	}
	return labelled{Resolver: r, label: label}
}
