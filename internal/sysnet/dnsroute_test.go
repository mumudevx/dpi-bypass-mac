//go:build darwin

package sysnet

import (
	"context"
	"strings"
	"testing"
)

const scutilSample = `DNS configuration

resolver #1
  search domain[0] : home
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 15 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : home
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  nameserver[2] : 127.0.0.1
  if_index : 15 (en0)
`

func TestActiveNameserversParsesScutil(t *testing.T) {
	cr := &scriptedRunner{out: map[string]string{"scutil --dns": scutilSample}}

	got := ActiveNameservers(context.Background(), cr)
	want := []string{"192.168.1.1", "8.8.8.8"}
	if len(got) != len(want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nameservers = %v, want %v", got, want)
		}
	}
}

func TestActiveNameserversSkipsLoopback(t *testing.T) {
	// A local resolver (dnsmasq, mDNSResponder proxy) must keep working: routing
	// 127.0.0.1 into the utun would break it and take DNS down with it.
	for _, ns := range ActiveNameservers(context.Background(), &scriptedRunner{
		out: map[string]string{"scutil --dns": scutilSample},
	}) {
		if strings.HasPrefix(ns, "127.") {
			t.Fatalf("loopback resolver %s was captured", ns)
		}
	}
}

func TestActiveNameserversSkipsIPv6(t *testing.T) {
	// Capture routes are IPv4-only, so a v6 nameserver can't be intercepted and
	// must not be handed to route(8) as if it could.
	for _, ns := range ActiveNameservers(context.Background(), &scriptedRunner{
		out: map[string]string{"scutil --dns": scutilSample},
	}) {
		if strings.Contains(ns, ":") {
			t.Fatalf("IPv6 nameserver %s was captured", ns)
		}
	}
}

func TestActiveNameserversEmptyWhenScutilSaysNothing(t *testing.T) {
	if got := ActiveNameservers(context.Background(), &scriptedRunner{out: map[string]string{}}); len(got) != 0 {
		t.Fatalf("nameservers = %v, want none", got)
	}
}

// On a home LAN the router is both the resolver and the default gateway. A /32
// for it does not intercept anything — the ARP-cloned host route on the uplink
// wins — and if it ever did take effect it would strip the default route of its
// next hop. Measured on a live run: with the /32 installed, `route -n get
// 192.168.0.1` still reported en0 and the ISP resolver answered normally.
func TestCapturableNameserversExcludesTheDefaultGateway(t *testing.T) {
	cr := &scriptedRunner{out: map[string]string{
		"scutil --dns":         scutilSample,
		"route -n get default": "    gateway: 192.168.1.1\n  interface: en0\n",
	}}

	got := CapturableNameservers(context.Background(), cr)
	if len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("capturable = %v, want [8.8.8.8]", got)
	}
}

func TestCapturableNameserversKeepsAllWhenNoGateway(t *testing.T) {
	cr := &scriptedRunner{out: map[string]string{"scutil --dns": scutilSample}}
	if got := CapturableNameservers(context.Background(), cr); len(got) != 2 {
		t.Fatalf("capturable = %v, want both resolvers", got)
	}
}

func TestCaptureHostsAddsAndTearsDownHostRoutes(t *testing.T) {
	fr := &fakeRunner{}
	rm := NewRouteManager("utun9", fr, nil)
	ctx := context.Background()

	if err := rm.CaptureHosts(ctx, []string{"192.168.1.1", "8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	// A /32 beats the LAN's /24, which is what pulls a router-provided resolver
	// into the utun instead of letting it stay on the physical link.
	if !fr.hasCall("route", "-q", "add", "-net", "192.168.1.1/32", "-interface", "utun9") {
		t.Fatal("did not add a host route for the LAN resolver")
	}
	if !fr.hasCall("route", "-q", "add", "-net", "8.8.8.8/32", "-interface", "utun9") {
		t.Fatal("did not add a host route for the public resolver")
	}

	rm.Teardown(ctx)
	if !fr.hasCall("route", "-q", "delete", "-net", "192.168.1.1/32", "-interface", "utun9") {
		t.Fatal("host route was not journalled for teardown")
	}
}

func TestCaptureHostsIgnoresGarbage(t *testing.T) {
	fr := &fakeRunner{}
	rm := NewRouteManager("utun9", fr, nil)

	if err := rm.CaptureHosts(context.Background(), []string{"not-an-ip", ""}); err != nil {
		t.Fatalf("CaptureHosts: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("route(8) was called with garbage input: %v", fr.calls)
	}
}
