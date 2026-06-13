package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// udpResolver queries a plain UDP DNS server (e.g. 77.88.8.8:53). Useful as a
// fallback to an un-poisoned upstream when DoH is unreachable.
type udpResolver struct {
	addr   string
	name   string
	client *dns.Client
}

// NewUDP builds a plain UDP DNS resolver. addr is host:port.
func NewUDP(addr, name string) (Resolver, error) {
	addr = ensurePort(addr, "53")
	return &udpResolver{
		addr:   addr,
		name:   labelOr(name, "udp:"+addr),
		client: &dns.Client{Net: "udp", Timeout: 4 * time.Second},
	}, nil
}

func (r *udpResolver) Label() string { return r.name }

func (r *udpResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	reply, _, err := r.client.ExchangeContext(ctx, m, r.addr)
	if err != nil {
		return nil, err
	}
	return extractA(reply), nil
}

// dotResolver queries DNS-over-TLS (host:853).
type dotResolver struct {
	addr   string
	name   string
	client *dns.Client
}

// NewDoT builds a DNS-over-TLS resolver. addr is host:port (port defaults 853).
func NewDoT(addr, name string) (Resolver, error) {
	hostport := ensurePort(addr, "853")
	host, _, _ := net.SplitHostPort(hostport)
	return &dotResolver{
		addr: hostport,
		name: labelOr(name, "dot:"+hostport),
		client: &dns.Client{
			Net:       "tcp-tls",
			Timeout:   5 * time.Second,
			TLSConfig: &tls.Config{ServerName: host},
		},
	}, nil
}

func (r *dotResolver) Label() string { return r.name }

func (r *dotResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	reply, _, err := r.client.ExchangeContext(ctx, m, r.addr)
	if err != nil {
		return nil, err
	}
	return extractA(reply), nil
}

func ensurePort(addr, defPort string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, defPort)
	}
	return addr
}

// ResolverFromSpec builds a resolver from a (type, url, name) triple. It returns
// an error for unknown types.
func ResolverFromSpec(typ, urlOrAddr, name string) (Resolver, error) {
	switch typ {
	case "doh":
		return NewDoH(urlOrAddr, name)
	case "dot":
		return NewDoT(urlOrAddr, name)
	case "udp", "":
		return NewUDP(urlOrAddr, name)
	default:
		return nil, fmt.Errorf("unknown resolver type %q", typ)
	}
}
