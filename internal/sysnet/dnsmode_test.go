package sysnet

import (
	"context"
	"path/filepath"
	"testing"
)

// dnsRunner answers -getdnsservers with a canned value and records every call.
type dnsRunner struct {
	calls [][]string
	get   string
}

func (d *dnsRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	d.calls = append(d.calls, append([]string{name}, args...))
	if name == "networksetup" && len(args) > 0 && args[0] == "-getdnsservers" {
		return d.get, nil
	}
	return "", nil
}

func (d *dnsRunner) hasCall(want ...string) bool {
	for _, c := range d.calls {
		if len(c) != len(want) {
			continue
		}
		match := true
		for i := range c {
			if c[i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func newTestDNSManager(t *testing.T, r CommandRunner) *DNSManager {
	t.Helper()
	return NewDNSManager(DNSConfig{
		Runner:    r,
		Resolver:  "1.1.1.1",
		StatePath: filepath.Join(t.TempDir(), "dns-backup.json"),
		Services:  []string{"Wi-Fi"},
	})
}

// A DHCP-provided resolver sits on-link, where no route can pull it into the
// utun. Pointing the service at an address the split-default routes do cover is
// what gets the query to serveDNS at all.
func TestDNSManagerPointsTheServiceAtTheCapturedResolver(t *testing.T) {
	r := &dnsRunner{get: "192.168.0.1\n"}
	m := newTestDNSManager(t, r)

	if err := m.Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !r.hasCall("networksetup", "-setdnsservers", "Wi-Fi", "1.1.1.1") {
		t.Fatalf("did not redirect the service resolver; calls: %v", r.calls)
	}
}

func TestDNSManagerRestoresThePreviousResolver(t *testing.T) {
	r := &dnsRunner{get: "192.168.0.1\n"}
	m := newTestDNSManager(t, r)

	if err := m.Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	m.Restore(context.Background())
	if !r.hasCall("networksetup", "-setdnsservers", "Wi-Fi", "192.168.0.1") {
		t.Fatalf("did not restore the previous resolver; calls: %v", r.calls)
	}
}

func TestDNSManagerRestoresToDHCPWhenNoneWereSet(t *testing.T) {
	r := &dnsRunner{get: "There aren't any DNS Servers set on Wi-Fi.\n"}
	m := newTestDNSManager(t, r)

	if err := m.Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	m.Restore(context.Background())
	if !r.hasCall("networksetup", "-setdnsservers", "Wi-Fi", "Empty") {
		t.Fatalf("did not hand the service back to DHCP; calls: %v", r.calls)
	}
}

// A hard kill leaves our own resolver in the service config. Recording it as
// "the original" would pin the user to it forever, exactly the trap the proxy
// manager already guards against.
func TestDNSManagerDoesNotRecordItsOwnResolverAsTheBackup(t *testing.T) {
	r := &dnsRunner{get: "1.1.1.1\n"}
	m := newTestDNSManager(t, r)

	if err := m.Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	m.Restore(context.Background())
	if !r.hasCall("networksetup", "-setdnsservers", "Wi-Fi", "Empty") {
		t.Fatalf("leftover state was treated as the user's own setting; calls: %v", r.calls)
	}
}

func TestDNSManagerKeepsMultipleResolvers(t *testing.T) {
	r := &dnsRunner{get: "192.168.0.1\n9.9.9.9\n"}
	m := newTestDNSManager(t, r)

	if err := m.Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	m.Restore(context.Background())
	if !r.hasCall("networksetup", "-setdnsservers", "Wi-Fi", "192.168.0.1", "9.9.9.9") {
		t.Fatalf("dropped one of the user's resolvers; calls: %v", r.calls)
	}
}

// Restore runs from a deferred cleanup and may run twice; the second pass must
// not push a stale value back over a later setting.
func TestDNSManagerRestoreIsIdempotent(t *testing.T) {
	r := &dnsRunner{get: "192.168.0.1\n"}
	m := newTestDNSManager(t, r)

	if err := m.Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	m.Restore(context.Background())
	n := len(r.calls)
	m.Restore(context.Background())
	if len(r.calls) != n {
		t.Fatalf("second Restore issued %v", r.calls[n:])
	}
}

// doctor recovers a hard-killed run from the state file, so the backup has to
// survive the process that wrote it.
func TestDNSManagerRestoresFromTheStateFile(t *testing.T) {
	state := filepath.Join(t.TempDir(), "dns-backup.json")
	cfg := DNSConfig{Runner: &dnsRunner{get: "192.168.0.1\n"}, Resolver: "1.1.1.1", StatePath: state, Services: []string{"Wi-Fi"}}
	if err := NewDNSManager(cfg).Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	fresh := &dnsRunner{}
	cfg.Runner = fresh
	NewDNSManager(cfg).Restore(context.Background())
	if !fresh.hasCall("networksetup", "-setdnsservers", "Wi-Fi", "192.168.0.1") {
		t.Fatalf("a new process could not recover the backup; calls: %v", fresh.calls)
	}
}
