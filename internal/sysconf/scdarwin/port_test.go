package scdarwin

import (
	"context"
	"net/netip"
	"testing"

	"github.com/mumudevx/dpb/internal/sysport"
)

// TestPortHandsOutTheInjectedRIB pins what New is for. route(8) writes and the
// RIB reads, and the two must never share a code path — but that separation is
// worth nothing if the Port quietly swaps in the kernel's own reader when a
// caller supplied one, because then every verification in the suite is
// answered by the developer's real routing table instead of the table the test
// just mutated.
func TestPortHandsOutTheInjectedRIB(t *testing.T) {
	f := newFakeSystem()
	p := New(f.env0())
	rib := p.Route().RIB()
	if rib == nil {
		t.Fatal("Route().RIB() is nil; there would be nothing verifying a route")
	}
	ok, err := rib.Exists(netip.MustParsePrefix("127.0.0.0/8"), "lo0")
	if err != nil {
		t.Fatalf("Exists through the Port's RIB: %v", err)
	}
	if !ok {
		t.Fatal("the Port answered from something other than the RIB it was given")
	}
	// And an Env with no RIB keeps none: "collect facts without a RIB" is an
	// error callers rely on, not an invitation to go and read the real table.
	if New(Env{Runner: f}).Route().RIB() != nil {
		t.Fatal("a Port built without a RIB invented one")
	}
}

// TestCapsNamesEveryCapability: macOS grants everything dpb has an Op for. The
// constant is spelled out rather than left implicit so that Windows' shortfall,
// when it lands, is a diff against something — and so a capability silently
// dropped from this list is a test failure rather than an Op that is skipped.
func TestCapsNamesEveryCapability(t *testing.T) {
	got := New(Env{}).Caps()
	for _, c := range []struct {
		name string
		cap  sysport.Caps
	}{
		{"CapProxyAuto", sysport.CapProxyAuto},
		{"CapProxyManual", sysport.CapProxyManual},
		{"CapDNSOverride", sysport.CapDNSOverride},
		{"CapRouteWrite", sysport.CapRouteWrite},
		{"CapIfaceConfig", sysport.CapIfaceConfig},
		{"CapSessionEnv", sysport.CapSessionEnv},
		{"CapPerService", sysport.CapPerService},
	} {
		if !got.Has(c.cap) {
			t.Errorf("macOS Caps is missing %s", c.name)
		}
	}
}

// TestIfaceAddrsReadsTheKernelBack is the verifier half of IfaceController: the
// address is written with ifconfig and read back through net.Interfaces(),
// which asks the kernel directly rather than asking the tool that just claimed
// to have configured it.
func TestIfaceAddrsReadsTheKernelBack(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500}
	ic := New(f.env0()).Iface()
	ctx := context.Background()

	cfg := sysport.IfaceConfig{Local: "10.255.0.1", Peer: "10.255.0.2", MTU: 1500}
	if err := ic.Configure(ctx, "utun4", cfg); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	addrs, err := ic.Addrs(ctx, "utun4")
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}
	if !hasAddr(addrs, "10.255.0.1") {
		t.Fatalf("Addrs = %v, want the address Configure installed", addrs)
	}

	if err := ic.Unconfigure(ctx, "utun4", cfg); err != nil {
		t.Fatalf("Unconfigure: %v", err)
	}
	addrs, err = ic.Addrs(ctx, "utun4")
	if err != nil {
		t.Fatalf("Addrs after Unconfigure: %v", err)
	}
	if hasAddr(addrs, "10.255.0.1") {
		t.Fatalf("Addrs = %v, want the address gone", addrs)
	}

	// An interface that does not exist carries no addresses. That is the right
	// answer, not an error: a utun goes away with the file descriptor that
	// owned it, and a revert that finds nothing has succeeded.
	got, err := ic.Addrs(ctx, "utun99")
	if err != nil || len(got) != 0 {
		t.Fatalf("Addrs(missing interface) = %v, %v; want no addresses and no error", got, err)
	}
}

func hasAddr(addrs []netip.Addr, want string) bool {
	w := netip.MustParseAddr(want)
	for _, a := range addrs {
		if a.Unmap() == w {
			return true
		}
	}
	return false
}
