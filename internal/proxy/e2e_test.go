//go:build e2e

// E2E smoke test that drives a real HTTPS request through the proxy with desync
// enabled, proving the fragmented ClientHello produces a valid TLS handshake.
// Requires network access. Run with: go test -tags e2e ./internal/proxy/
package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"github.com/mumudevx/dpi-bypass-mac/internal/dns"
)

func TestE2EHTTPSThroughProxy(t *testing.T) {
	eng, err := desync.New(desync.Spec{Emitter: "split-at-sni", FragWindow: 1})
	if err != nil {
		t.Fatal(err)
	}
	res, err := dns.NewDoH("https://cloudflare-dns.com/dns-query", "cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	chain := dns.NewChain([]dns.Resolver{res}, time.Minute, nil)

	srv := New(Options{
		Resolver:    chain,
		Apply:       EngineApply(eng),
		DesyncPorts: map[int]bool{443: true},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	for _, site := range []string{"https://example.com", "https://www.cloudflare.com"} {
		resp, err := client.Get(site)
		if err != nil {
			t.Fatalf("GET %s through proxy: %v", site, err)
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			t.Fatalf("GET %s: status %d", site, resp.StatusCode)
		}
		t.Logf("%s → %d", site, resp.StatusCode)
	}
}
