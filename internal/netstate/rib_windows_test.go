//go:build windows

package netstate

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/windows"
)

// loopbackName is the name this machine's loopback interface answers to.
//
// It is discovered rather than written down because Windows names adapters
// with a LOCALIZED FriendlyName — "Loopback Pseudo-Interface 1" in English and
// something else on a Turkish or German install — and scwindows' kernelRIB
// fills RouteEntry.Iface from exactly that string (net.Interface.Name, which
// interface_windows.go takes from the adapter's FriendlyName). A literal here
// would be a test that passes in one locale and fails in another, which is the
// same class of defect the scwindows package comment refuses to parse tool
// output for.
func loopbackName(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("enumerate interfaces: %v", err)
	}
	for _, in := range ifs {
		if in.Flags&net.FlagLoopback != 0 {
			return in.Name
		}
	}
	t.Skip("this machine reports no loopback interface")
	return ""
}

// TestLiveRIBReadableUnelevated is rib_darwin_test.go's
// TestLiveRIBReadableUnprivileged for the IP Helper reader: the acceptance
// criterion is the same one — the routing table must be readable WITHOUT
// elevation, because proxy mode never elevates and still has to verify what it
// did — and it is asserted here against GetIpForwardTable2 rather than
// AF_ROUTE.
//
// The guard is a token elevation check rather than a uid: os.Geteuid() returns
// -1 on Windows, so the darwin version's "only meaningful as a non-root uid"
// skip could never fire here and the test would have claimed an unprivileged
// read it never made.
func TestLiveRIBReadableUnelevated(t *testing.T) {
	if elevated() {
		t.Skip("this test is only meaningful for an unelevated token")
	}
	rib := NewRIB()
	routes, err := rib.Routes()
	if err != nil {
		t.Fatalf("Routes() unelevated: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("the live routing table came back empty")
	}
	t.Logf("read %d routes from the live RIB unelevated", len(routes))

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

	// Loopback is present on every Windows machine and is the one route this
	// test can assert on without knowing anything about the network. The /8 is
	// what Windows installs for it, the same prefix darwin's lo0 carries.
	lo := loopbackName(t)
	if ok, err := rib.Exists(netip.MustParsePrefix("127.0.0.0/8"), lo); err != nil || !ok {
		t.Fatalf("Exists(127.0.0.0/8, %q) = %v, %v", lo, ok, err)
	}
	if ok, _ := rib.Exists(netip.MustParsePrefix("203.0.113.0/24"), lo); ok {
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

	// ScopedDefault must not return the unscoped default under any name. On
	// Windows nothing sets RTF_IFSCOPE's equivalent, so the honest answer here
	// is "not found" — and returning the unscoped default instead would make
	// every tun-mode uplink check believe a scoped route it never installed
	// was already there.
	if e, ok, err := rib.ScopedDefault(lo); err != nil {
		t.Fatalf("ScopedDefault: %v", err)
	} else if ok && !e.Scoped {
		t.Fatalf("ScopedDefault returned an unscoped route: %s", e)
	}
}

// elevated reports whether this process's token is elevated. A failure to ask
// is read as "not elevated", which is the same direction paths_windows.go's
// resolve() takes: the answer only gates a skip.
func elevated() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
