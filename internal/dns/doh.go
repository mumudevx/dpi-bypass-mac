package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// bootstrap maps well-known DoH hostnames to their anycast IPs so the DoH
// endpoint itself can be reached without relying on (possibly poisoned) system
// DNS. TLS still uses the hostname for SNI and certificate validation.
var bootstrap = map[string][]string{
	"cloudflare-dns.com": {"1.1.1.1", "1.0.0.1"},
	"dns.google":         {"8.8.8.8", "8.8.4.4"},
	"dns.quad9.net":      {"9.9.9.9", "149.112.112.112"},
	"dns.mullvad.net":    {"194.242.2.2"},
}

type doh struct {
	endpoint string
	name     string
	client   *http.Client
}

// NewDoH builds a DoH resolver. The HTTP client uses a bootstrap dialer so the
// DoH host resolves via known IPs instead of system DNS.
func NewDoH(endpoint, name string) (Resolver, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH url %q: %w", endpoint, err)
	}
	transport := &http.Transport{
		DialContext:         bootstrapDialer(u.Hostname()),
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &doh{
		endpoint: endpoint,
		name:     labelOr(name, "doh:"+u.Hostname()),
		client:   &http.Client{Timeout: 8 * time.Second, Transport: transport},
	}, nil
}

func (d *doh) Label() string { return d.name }

func (d *doh) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack doh reply: %w", err)
	}
	return extractA(reply), nil
}

// bootstrapDialer returns a DialContext that substitutes a bootstrap IP for the
// given host while leaving all other hosts to the default resolver.
func bootstrapDialer(host string) func(context.Context, string, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	ips := bootstrap[host]
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, port, err := net.SplitHostPort(addr)
		if err != nil {
			return d.DialContext(ctx, network, addr)
		}
		if h == host && len(ips) > 0 {
			var lastErr error
			for _, ip := range ips {
				conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}
		return d.DialContext(ctx, network, addr)
	}
}

func extractA(m *dns.Msg) []net.IP {
	var ips []net.IP
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}
	return ips
}

func labelOr(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}
