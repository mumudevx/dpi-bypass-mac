package resolve

import (
	"net/netip"
	"testing"
)

// TestDefaultEndpointsMatchTheShippedChain pins the order and the addresses the
// plan's Turkey profile specifies. Two of the five rungs are measurements
// (MEASUREMENTS.md §2: 77.88.8.8:1253 and 9.9.9.9:9953 answer for blocked names
// while port 53 does not), and the DoH bootstrap addresses are hardcoded
// because the update channel that would deliver them is itself censorable.
func TestDefaultEndpointsMatchTheShippedChain(t *testing.T) {
	got := DefaultEndpoints()
	want := []struct {
		label     string
		transport string
		target    string
		boot      []string
	}{
		{"doh-cloudflare", "doh", "https://cloudflare-dns.com/dns-query", []string{"1.1.1.1", "1.0.0.1"}},
		{"doh-google", "doh", "https://dns.google/dns-query", []string{"8.8.8.8", "8.8.4.4"}},
		{"dot-quad9", "dot", "9.9.9.9:853", nil},
		{"udp-yandex-1253", "udp-alt", "77.88.8.8:1253", nil},
		{"udp-quad9-9953", "udp-alt", "9.9.9.9:9953", nil},
	}
	if len(got) != len(want) {
		t.Fatalf("chain has %d rungs, want %d", len(got), len(want))
	}
	for i, w := range want {
		e := got[i]
		if e.Label != w.label || e.Transport != w.transport || e.Target != w.target {
			t.Fatalf("rung %d = %+v, want %s/%s/%s", i, e, w.label, w.transport, w.target)
		}
		if len(e.Bootstrap) != len(w.boot) {
			t.Fatalf("rung %d has %d bootstrap addresses, want %d", i, len(e.Bootstrap), len(w.boot))
		}
		for j, b := range w.boot {
			if e.Bootstrap[j] != netip.MustParseAddr(b) {
				t.Fatalf("rung %d bootstrap %d = %s, want %s", i, j, e.Bootstrap[j], b)
			}
		}
	}
	// Plain UDP on port 53 is deliberately absent: §2 measures it as
	// per-QNAME dropped for exactly the names this tool exists to reach.
	for _, e := range got {
		if e.Transport == "udp" {
			t.Fatalf("port 53 must not be in the shipped chain: %+v", e)
		}
	}
}

func TestDefaultResolversBuild(t *testing.T) {
	rs, err := DefaultResolvers(nil, nil)
	if err != nil {
		t.Fatalf("DefaultResolvers: %v", err)
	}
	if len(rs) != len(DefaultEndpoints()) {
		t.Fatalf("built %d resolvers, want %d", len(rs), len(DefaultEndpoints()))
	}
	for i, e := range DefaultEndpoints() {
		if rs[i].Label() != e.Label {
			t.Fatalf("resolver %d label = %q, want the configured %q", i, rs[i].Label(), e.Label)
		}
		if rs[i].Transport() != e.Transport {
			t.Fatalf("resolver %d transport = %q, want %q", i, rs[i].Transport(), e.Transport)
		}
	}
}

func TestEndpointNewRejectsBadConfiguration(t *testing.T) {
	if _, err := (Endpoint{Label: "x", Transport: "tcp", Target: "8.8.8.8:53"}).New(nil, nil); err == nil {
		t.Fatal("an unknown transport must be refused")
	}
	if _, err := (Endpoint{Label: "x", Transport: "doh", Target: "https://dns.example/q"}).New(nil, nil); err == nil {
		t.Fatal("a DoH endpoint without bootstrap must be refused")
	}
	if _, err := (Endpoint{Label: "x", Transport: "dot", Target: "dns.quad9.net:853"}).New(nil, nil); err == nil {
		t.Fatal("a DoT hostname must be refused")
	}
	if _, err := (Endpoint{Label: "x", Transport: "udp-alt", Target: "dns.example:1253"}).New(nil, nil); err == nil {
		t.Fatal("a UDP hostname must be refused")
	}
	// A single bad endpoint fails the whole build: silently shipping a shorter
	// chain than the measured one is how a user ends up on a ruled-out
	// transport.
	if _, err := (Endpoint{Transport: "doh", Target: "https://dns.example/q"}).New(nil, nil); err == nil {
		t.Fatal("expected failure")
	}
}

func TestRelabelKeepsTheUnderlyingResolver(t *testing.T) {
	base, err := NewUDP("original", "77.88.8.8:1253", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := relabel(base, ""); got.Label() != "original" {
		t.Fatalf("an empty label must not override, got %q", got.Label())
	}
	got := relabel(base, "configured")
	if got.Label() != "configured" {
		t.Fatalf("label = %q", got.Label())
	}
	if got.Transport() != base.Transport() {
		t.Fatalf("relabelling must not change the transport: %q", got.Transport())
	}
}
