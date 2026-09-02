package testnet

import (
	"errors"
	"net/netip"
	"testing"
)

func TestRIBDefaultPrefersIPv4(t *testing.T) {
	r := NewRIB(
		Default6("fe80::1", "en0", 14),
		Default4("192.168.0.1", "en0", 14),
	)
	got, ok, err := r.Default()
	if err != nil || !ok {
		t.Fatalf("Default() = %v, %v, %v", got, ok, err)
	}
	if !got.Dst.Addr().Is4() {
		t.Fatalf("Default() = %v, want the v4 default: it is the one that names the uplink", got)
	}
	if got.Gateway.String() != "192.168.0.1" || got.Iface != "en0" {
		t.Fatalf("Default() = %+v", got)
	}
}

func TestRIBDefaultFallsBackToIPv6(t *testing.T) {
	r := NewRIB(Default6("fe80::1", "en0", 14))
	got, ok, err := r.Default()
	if err != nil || !ok || got.Dst.Addr().Is4() {
		t.Fatalf("Default() = %v, %v, %v", got, ok, err)
	}
}

// TestRIBScopedDefaultIsNotTheDefault is the distinction that stops Ctrl-C from
// deleting a VPN's routes: a VPN installs an interface-scoped default, and an
// unscoped Default() query must not see it.
func TestRIBScopedDefaultIsNotTheDefault(t *testing.T) {
	r := NewRIB(
		Default4("192.168.0.1", "en0", 14),
		ScopedDefault4("10.8.0.1", "utun4", 20),
	)
	def, ok, err := r.Default()
	if err != nil || !ok {
		t.Fatalf("Default() = %v, %v, %v", def, ok, err)
	}
	if def.Iface != "en0" {
		t.Fatalf("Default() = %+v, want the unscoped en0 route", def)
	}
	sc, ok, err := r.ScopedDefault("utun4")
	if err != nil || !ok {
		t.Fatalf("ScopedDefault(utun4) = %v, %v, %v", sc, ok, err)
	}
	if sc.Gateway.String() != "10.8.0.1" {
		t.Fatalf("ScopedDefault(utun4) = %+v", sc)
	}
	if _, ok, _ := r.ScopedDefault("utun9"); ok {
		t.Error("ScopedDefault invented a route for an interface with none")
	}
}

func TestRIBExistsAndRemove(t *testing.T) {
	host := netip.MustParsePrefix("1.2.3.4/32")
	r := NewRIB(Host4("1.2.3.4", "192.168.0.1", "en0", 14))

	if ok, err := r.Exists(host, "en0"); err != nil || !ok {
		t.Fatalf("Exists(en0) = %v, %v", ok, err)
	}
	if ok, err := r.Exists(host, ""); err != nil || !ok {
		t.Fatalf("Exists(any iface) = %v, %v", ok, err)
	}
	if ok, _ := r.Exists(host, "utun4"); ok {
		t.Error("Exists matched the wrong interface")
	}
	if ok, _ := r.Exists(netip.MustParsePrefix("5.6.7.8/32"), ""); ok {
		t.Error("Exists matched a route that is not there")
	}

	if !r.Remove(host, "en0") {
		t.Fatal("Remove reported nothing removed")
	}
	if ok, _ := r.Exists(host, ""); ok {
		t.Fatal("route survived Remove")
	}
	if r.Remove(host, "en0") {
		t.Error("Remove reported a second removal")
	}
}

// TestRIBAddReplacesSameDestination mirrors the kernel: adding a route for a
// destination that already has one on the same interface replaces it rather than
// producing a duplicate, so a test cannot accidentally assert against a table
// shape the kernel would never produce.
func TestRIBAddReplacesSameDestination(t *testing.T) {
	r := NewRIB()
	r.Add(Host4("1.2.3.4", "192.168.0.1", "en0", 14))
	r.Add(Host4("1.2.3.4", "192.168.0.254", "en0", 14))
	r.Add(Host4("1.2.3.4", "10.8.0.1", "utun4", 20))

	rs, err := r.Routes()
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("Routes() = %v, want one per interface", rs)
	}
	for _, e := range rs {
		if e.Iface == "en0" && e.Gateway.String() != "192.168.0.254" {
			t.Errorf("en0 route was not replaced: %+v", e)
		}
	}
}

// TestRIBErrorSurfaces pins that an unreadable RIB is an error and not an
// implicit "the route is absent". Treating a failed read as absence is how a
// Verify silently passes on a machine where AF_ROUTE cannot be opened.
func TestRIBErrorSurfaces(t *testing.T) {
	boom := errors.New("route socket closed")
	r := NewRIB(Default4("192.168.0.1", "en0", 14))
	r.SetErr(boom)

	if _, err := r.Routes(); !errors.Is(err, boom) {
		t.Errorf("Routes err = %v", err)
	}
	if _, _, err := r.Default(); !errors.Is(err, boom) {
		t.Errorf("Default err = %v", err)
	}
	if _, _, err := r.ScopedDefault("utun4"); !errors.Is(err, boom) {
		t.Errorf("ScopedDefault err = %v", err)
	}
	if _, err := r.Exists(netip.MustParsePrefix("0.0.0.0/0"), ""); !errors.Is(err, boom) {
		t.Errorf("Exists err = %v", err)
	}
}

// TestRIBCountsReads is what a test uses to prove a Verify actually consulted
// the kernel rather than trusting route(8)'s exit code.
func TestRIBCountsReads(t *testing.T) {
	r := NewRIB()
	if r.Reads() != 0 {
		t.Fatalf("Reads() = %d before any read", r.Reads())
	}
	_, _, _ = r.Default()
	_, _ = r.Exists(netip.MustParsePrefix("0.0.0.0/0"), "")
	if r.Reads() != 2 {
		t.Fatalf("Reads() = %d, want 2", r.Reads())
	}
}

// TestRIBRoutesIsACopy stops a caller from mutating the fake through its own
// return value.
func TestRIBRoutesIsACopy(t *testing.T) {
	r := NewRIB(Default4("192.168.0.1", "en0", 14))
	rs, err := r.Routes()
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	rs[0].Iface = "tampered"
	again, _ := r.Routes()
	if again[0].Iface != "en0" {
		t.Fatal("Routes() aliased the fake's own slice")
	}
	r.Set()
	if again, _ := r.Routes(); len(again) != 0 {
		t.Fatalf("Set() did not clear the table: %v", again)
	}
}
