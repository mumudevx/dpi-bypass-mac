package resolve

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
)

const (
	dohContentType = "application/dns-message"
	dohBodyMax     = 64 << 10
	dohTimeout     = 8 * time.Second
	dohTLSTimeout  = 5 * time.Second
	dohIdle        = 30 * time.Second
)

type dohResolver struct {
	label  string
	url    string
	host   string
	boot   []netip.Addr
	client *http.Client
	turn   atomic.Uint32
}

// NewDoH builds an RFC 8484 DoH resolver.
//
// bootstrap is mandatory. The endpoint's hostname is used for exactly two
// things — the TLS ServerName and the HTTP Host header — and is never handed to
// a resolver: doing so is the fall-through MEASUREMENTS.md §5.4 records, where
// the system resolver answered with the BTK sinkhole and every subsequent
// measurement was taken against a blackhole.
func NewDoH(endpoint string, bootstrap []netip.Addr, dial DialFunc) (Resolver, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve: DoH endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("resolve: DoH endpoint %q must be https, got %q", endpoint, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("resolve: DoH endpoint %q has no host", endpoint)
	}
	boot := make([]netip.Addr, 0, len(bootstrap))
	for _, a := range bootstrap {
		if a.IsValid() {
			boot = append(boot, a)
		}
	}
	if len(boot) == 0 {
		return nil, fmt.Errorf("resolve: DoH endpoint %q needs at least one bootstrap address; "+
			"dialling the hostname would fall through to the system resolver (MEASUREMENTS.md §5.4)", endpoint)
	}

	r := &dohResolver{label: "doh-" + host, url: u.String(), host: host, boot: boot}
	r.client = &http.Client{
		Timeout: dohTimeout,
		Transport: &http.Transport{
			// Explicitly nil, not http.ProxyFromEnvironment. dpb itself sets
			// HTTPS_PROXY through `launchctl setenv`, so an environment-aware
			// transport here would route the tool's own DNS back into the
			// tool's own proxy listener and deadlock the first query.
			Proxy:               nil,
			DialContext:         r.dialBootstrap(dial),
			TLSClientConfig:     &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     dohIdle,
			TLSHandshakeTimeout: dohTLSTimeout,
		},
	}
	return r, nil
}

// dialBootstrap discards the address net/http derived from the URL and dials a
// bootstrap IP instead. The discard is the whole point of the function: addr
// arrives as "cloudflare-dns.com:443", and passing it to any dialer is what
// hands the name to the system resolver.
func (r *dohResolver) dialBootstrap(dial DialFunc) func(context.Context, string, string) (net.Conn, error) {
	fallback := &net.Dialer{Timeout: dohTLSTimeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			portStr = "443"
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("resolve: %s: bad port in %q: %w", r.label, addr, err)
		}
		// Rotate on every dial so a bootstrap address that has gone dark costs
		// one attempt rather than every attempt.
		start := int(r.turn.Add(1)-1) % len(r.boot)
		var lastErr error
		for i := range r.boot {
			ip := r.boot[(start+i)%len(r.boot)]
			target := netip.AddrPortFrom(ip, uint16(port)).String()
			var c net.Conn
			if dial != nil {
				c, lastErr = dial(ctx, network, target)
			} else {
				c, lastErr = fallback.DialContext(ctx, network, target)
			}
			if lastErr == nil {
				return c, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, fmt.Errorf("resolve: %s: no bootstrap address reachable: %w", r.label, lastErr)
	}
}

func (r *dohResolver) Label() string     { return r.label }
func (r *dohResolver) Transport() string { return "doh" }

func (r *dohResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < headerLen {
		return nil, ErrShortMessage
	}
	callerID := binary.BigEndian.Uint16(query[0:2])
	out := make([]byte, len(query))
	copy(out, query)
	// RFC 8484 §4.1: the ID SHOULD be 0 so responses are cacheable by HTTP.
	binary.BigEndian.PutUint16(out[0:2], 0)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("resolve: %s: build request: %w", r.label, err)
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)
	req.Header.Set("User-Agent", buildinfo.UserAgent())

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve: %s: query %s: %w", r.label, questionLabel(query), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a little so the connection can be reused; a DoH error body is
		// tiny and reading it is cheaper than tearing down the TLS session.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("resolve: %s: HTTP %d for %s", r.label, resp.StatusCode, questionLabel(query))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohBodyMax+1))
	if err != nil {
		return nil, fmt.Errorf("resolve: %s: read body: %w", r.label, err)
	}
	if len(body) > dohBodyMax {
		return nil, fmt.Errorf("resolve: %s: answer larger than %d bytes", r.label, dohBodyMax)
	}
	if len(body) < headerLen {
		return nil, fmt.Errorf("resolve: %s: %w", r.label, ErrShortMessage)
	}
	if !IsResponse(body) || !SameQuestion(out, body) {
		return nil, fmt.Errorf("resolve: %s: answer does not match the question %s",
			r.label, questionLabel(query))
	}
	binary.BigEndian.PutUint16(body[0:2], callerID)
	return body, nil
}
