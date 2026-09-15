//go:build darwin

// The live-RIB acceptance test, which asserts two things only a BSD kernel
// answers.
//
// First, interface NAMES: `lo0` and `en0` are darwin's, and the loopback
// assertion is the one route this test can pin without knowing anything about
// the machine's network. Linux calls the same interface `lo`; Windows calls it
// "Loopback Pseudo-Interface 1" and LOCALIZES that string, so no literal works
// there at all — rib_windows_test.go discovers the name from net.Interfaces()
// instead, which is why its version is a separate test rather than a shared one
// with a platform-dependent constant.
//
// Second, a POSIX uid. `os.Geteuid()` returns -1 on Windows, so the
// "only meaningful as a non-root uid" guard neither fires nor means anything
// there; Windows' equivalent question is a token elevation check, which
// rib_windows_test.go asks instead.
//
// The function body is unchanged from rib_test.go, where it lived until the
// Windows suite started running.

package netstate

import (
	"net/netip"
	"os"
	"testing"
)

// TestLiveRIBReadableUnprivileged is the acceptance criterion for the AF_ROUTE
// reader: it must work as an ordinary user, because the proxy front-end runs
// without sudo and still has to verify what it did to the routing table.
func TestLiveRIBReadableUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test is only meaningful as a non-root uid")
	}
	rib := NewRIB()
	routes, err := rib.Routes()
	if err != nil {
		t.Fatalf("Routes() as uid %d: %v", os.Getuid(), err)
	}
	if len(routes) == 0 {
		t.Fatal("the live routing table came back empty")
	}
	t.Logf("read %d routes from the live RIB as uid %d", len(routes), os.Getuid())

	sawV4, sawIface := false, false
	for _, r := range routes {
		if !r.Dst.IsValid() {
			t.Fatalf("route with an invalid destination: %+v", r)
		}
		if r.Dst.Addr().Is4() {
			sawV4 = true
		}
		if r.Iface != "" {
			sawIface = true
		}
	}
	if !sawV4 {
		t.Fatal("no IPv4 routes were parsed")
	}
	if !sawIface {
		t.Fatal("no route was attributed to an interface")
	}

	// Loopback is present on every macOS machine and is the one route we can
	// assert on without knowing anything about this network.
	if ok, err := rib.Exists(netip.MustParsePrefix("127.0.0.0/8"), "lo0"); err != nil || !ok {
		t.Fatalf("Exists(127.0.0.0/8, lo0) = %v, %v", ok, err)
	}
	if ok, _ := rib.Exists(netip.MustParsePrefix("203.0.113.0/24"), "en0"); ok {
		t.Fatal("Exists reported a route to a TEST-NET-3 prefix")
	}

	if def, ok, err := rib.Default(); err != nil {
		t.Fatalf("Default(): %v", err)
	} else if ok {
		if def.Dst.Bits() != 0 {
			t.Fatalf("Default() returned %s, which is not a default route", def.Dst)
		}
		if def.Scoped {
			t.Fatalf("Default() returned a scoped route: %s", def)
		}
		t.Logf("default route: %s", def)
	}

	// ScopedDefault must not return the unscoped default under any name.
	if e, ok, err := rib.ScopedDefault("lo0"); err != nil {
		t.Fatalf("ScopedDefault: %v", err)
	} else if ok && !e.Scoped {
		t.Fatalf("ScopedDefault returned an unscoped route: %s", e)
	}
}
