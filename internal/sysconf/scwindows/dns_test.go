//go:build windows

package scwindows

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// Like every other test in this package, these can only RUN on a Windows host
// and CI does not yet have one (see iphlp_test.go). GOOS=windows go vet
// compiles them and go test -c proves they link; neither proves an assertion
// has ever passed.
//
// Set and Clear are the one place in this whole package that goes through
// sysport.Runner rather than a Win32 call — every other controller (route,
// iface, proxy) talks straight to iphlpapi/wininet/winhttp/the registry, so
// there was nowhere to inject a fake before this file. That makes the argv
// this file hands netsh the part of dns.go a fake CAN pin without a Windows
// host, and it is worth pinning: windows.go's Contract 1 depends on nobody
// ever adding a "netsh" entry to runner.go's liar table, and a typo'd flag
// name here (e.g. "validate=yes" surviving a refactor) would not fail to
// compile — it would just make Set slower or, per that same Contract 1,
// silently wrong on a machine whose language this package cannot read.

// scriptedNetsh is a minimal sysport.Runner fake that records every argv it
// is asked to run, in call order, as one space-joined string, and returns a
// scripted exit code for it.
type scriptedNetsh struct {
	calls []string
	fail  map[string]bool
}

func (r *scriptedNetsh) Run(_ context.Context, name string, args ...string) sysport.Result {
	argv := append([]string{name}, args...)
	line := strings.Join(argv, " ")
	r.calls = append(r.calls, line)
	res := sysport.Result{Argv: argv}
	if r.fail[line] {
		res.Code = 1
	}
	return res
}

// TestDNSSetSplitsFamiliesAndIndexesAdditionalServers pins the exact netsh
// invocations Set makes for a server list spanning both address families:
// one `set dnsservers` per family present (the primary, register=primary),
// followed by one `add dnsservers` per additional server in that family,
// indexed from 2 — regardless of how the two families were interleaved in
// the input, ipv4 always precedes ipv6 (Set's own order, not dnsFamilies',
// since Set builds the two family lists first and then acts on each present
// one in a fixed order).
func TestDNSSetSplitsFamiliesAndIndexesAdditionalServers(t *testing.T) {
	r := &scriptedNetsh{}
	c := dnsCtl{p: &port{run: r}}

	servers := []string{"127.0.0.1", "2001:4860:4860::8888", "1.1.1.1", "2606:4700:4700::1111"}
	if err := c.Set(context.Background(), "Ethernet", servers); err != nil {
		t.Fatalf("Set: %v", err)
	}

	want := []string{
		"netsh interface ipv4 set dnsservers name=Ethernet source=static address=127.0.0.1 register=primary validate=no",
		"netsh interface ipv4 add dnsservers name=Ethernet address=1.1.1.1 index=2 validate=no",
		"netsh interface ipv6 set dnsservers name=Ethernet source=static address=2001:4860:4860::8888 register=primary validate=no",
		"netsh interface ipv6 add dnsservers name=Ethernet address=2606:4700:4700::1111 index=2 validate=no",
	}
	if diff := cmp.Diff(want, r.calls); diff != "" {
		t.Errorf("netsh argv mismatch (-want +got):\n%s", diff)
	}
}

// TestDNSSetSingleServerNeverCallsAdd: a one-server list must not touch `add
// dnsservers` at all — servers[1:] is empty, and slicing it must not panic.
func TestDNSSetSingleServerNeverCallsAdd(t *testing.T) {
	r := &scriptedNetsh{}
	c := dnsCtl{p: &port{run: r}}
	if err := c.Set(context.Background(), "Ethernet", []string{"127.0.0.1"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	want := []string{
		"netsh interface ipv4 set dnsservers name=Ethernet source=static address=127.0.0.1 register=primary validate=no",
	}
	if diff := cmp.Diff(want, r.calls); diff != "" {
		t.Errorf("netsh argv mismatch (-want +got):\n%s", diff)
	}
}

// TestDNSSetRefusesAnEmptyServerList: a caller with nothing to set gets an
// error, not a silent no-op that never touches netsh at all — matching
// internal/netstate/op_dns.go's own dnsOp.prepare, which refuses to Apply an
// Op with no servers in the first place.
func TestDNSSetRefusesAnEmptyServerList(t *testing.T) {
	r := &scriptedNetsh{}
	c := dnsCtl{p: &port{run: r}}
	if err := c.Set(context.Background(), "Ethernet", nil); err == nil {
		t.Fatal("Set with no servers returned no error")
	}
	if len(r.calls) != 0 {
		t.Errorf("Set with no servers still ran netsh: %v", r.calls)
	}
}

// TestDNSSetStopsAFamilyOnItsFirstFailure: unlike Clear, Set's two family
// calls are not independent — the `add` calls for a family are meaningless
// once that family's `set` failed to establish a primary, so Set must return
// immediately rather than trying to layer `add` on a `set` that never landed.
func TestDNSSetStopsAFamilyOnItsFirstFailure(t *testing.T) {
	r := &scriptedNetsh{fail: map[string]bool{
		"netsh interface ipv4 set dnsservers name=Ethernet source=static address=127.0.0.1 register=primary validate=no": true,
	}}
	c := dnsCtl{p: &port{run: r}}
	err := c.Set(context.Background(), "Ethernet", []string{"127.0.0.1", "1.1.1.1"})
	if err == nil {
		t.Fatal("Set with a failing ipv4 `set` returned no error")
	}
	if len(r.calls) != 1 {
		t.Errorf("netsh calls = %v, want exactly the one failing `set` (no `add` after it)", r.calls)
	}
}

// TestDNSClearTriesBothFamiliesAndReturnsTheFirstFailure: Clear always
// attempts both protocols even when the first fails, and reports the first
// failure — the same fail()-and-keep-going shape proxyCtl.Restore uses.
func TestDNSClearTriesBothFamiliesAndReturnsTheFirstFailure(t *testing.T) {
	r := &scriptedNetsh{fail: map[string]bool{
		"netsh interface ipv4 set dnsservers name=Ethernet source=dhcp": true,
	}}
	c := dnsCtl{p: &port{run: r}}
	if err := c.Clear(context.Background(), "Ethernet"); err == nil {
		t.Fatal("Clear with a failing ipv4 call returned no error")
	}
	want := []string{
		"netsh interface ipv4 set dnsservers name=Ethernet source=dhcp",
		"netsh interface ipv6 set dnsservers name=Ethernet source=dhcp",
	}
	if diff := cmp.Diff(want, r.calls); diff != "" {
		t.Errorf("netsh argv mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitDNSServersByFamily pins the ordering and family split a mixed list
// produces, independent of interleaving in the input.
func TestSplitDNSServersByFamily(t *testing.T) {
	v4, v6, err := splitDNSServersByFamily([]string{"127.0.0.1", "2001:db8::1", "1.1.1.1", "::1"})
	if err != nil {
		t.Fatalf("splitDNSServersByFamily: %v", err)
	}
	if diff := cmp.Diff([]string{"127.0.0.1", "1.1.1.1"}, v4); diff != "" {
		t.Errorf("v4 mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"2001:db8::1", "::1"}, v6); diff != "" {
		t.Errorf("v6 mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitDNSServersByFamilyUnmapsA4In6Address guards the exact bug fixed
// while writing this file: netip.Addr.String() on an UN-unmapped 4-in-6
// address renders "::ffff:1.2.3.4", which `netsh interface ipv4` (dotted
// decimal only) would reject. Unmap() must run before String() in the v4
// branch, not after routing to the v4 list based on Is4In6 alone.
func TestSplitDNSServersByFamilyUnmapsA4In6Address(t *testing.T) {
	v4, v6, err := splitDNSServersByFamily([]string{"::ffff:1.2.3.4"})
	if err != nil {
		t.Fatalf("splitDNSServersByFamily: %v", err)
	}
	if diff := cmp.Diff([]string{"1.2.3.4"}, v4); diff != "" {
		t.Errorf("v4 mismatch (-want +got):\n%s", diff)
	}
	if len(v6) != 0 {
		t.Errorf("v6 = %v, want none", v6)
	}
}

// TestSplitDNSServersByFamilyRejectsANonAddress: a server list this package
// cannot even parse as an IP must fail loudly rather than being silently
// dropped or forwarded to netsh verbatim.
func TestSplitDNSServersByFamilyRejectsANonAddress(t *testing.T) {
	if _, _, err := splitDNSServersByFamily([]string{"resolver.example"}); err == nil {
		t.Error("splitDNSServersByFamily accepted a non-address string")
	}
}

// fakeDefaultRIB is a minimal sysport.RIBReader fake, just enough to drive
// Live's one call to Default() without a real routing table.
type fakeDefaultRIB struct {
	entry sysport.RouteEntry
	ok    bool
	err   error
}

func (f fakeDefaultRIB) Routes() ([]sysport.RouteEntry, error) { return nil, nil }
func (f fakeDefaultRIB) Default() (sysport.RouteEntry, bool, error) {
	return f.entry, f.ok, f.err
}
func (f fakeDefaultRIB) ScopedDefault(string) (sysport.RouteEntry, bool, error) {
	return sysport.RouteEntry{}, false, nil
}
func (f fakeDefaultRIB) Exists(netip.Prefix, string) (bool, error) { return false, nil }

var _ sysport.RIBReader = fakeDefaultRIB{}

// TestDNSLiveWithNoDefaultRouteReportsNoServers: a machine with nothing
// treated as "the" default route answers Live with no servers, not an
// error — the same shape ifaceCtl.Addrs gives a vanished tunnel adapter.
func TestDNSLiveWithNoDefaultRouteReportsNoServers(t *testing.T) {
	c := dnsCtl{p: &port{rib: fakeDefaultRIB{ok: false}}}
	got, err := c.Live(context.Background())
	if err != nil {
		t.Fatalf("Live: %v", err)
	}
	if got != nil {
		t.Errorf("Live = %v, want nil", got)
	}
}

// TestDNSLivePropagatesADefaultRouteReadFailure: a RIB read that genuinely
// broke is an error, not a silent "nothing is live" — those are different
// answers and op_dns.go's Verify needs to be able to tell them apart.
func TestDNSLivePropagatesADefaultRouteReadFailure(t *testing.T) {
	want := errors.New("boom")
	c := dnsCtl{p: &port{rib: fakeDefaultRIB{err: want}}}
	if _, err := c.Live(context.Background()); !errors.Is(err, want) {
		t.Errorf("Live error = %v, want it to wrap %v", err, want)
	}
}

// TestDNSServerAddrsOfDecodesTheList builds the same linked-list shape
// GetAdaptersAddresses hands back for FirstDnsServerAddress by hand — the
// same construction iface_test.go's TestUnicastAddrsOfDecodesTheList uses for
// FirstUnicastAddress — and checks dnsServerAddrsOf walks it, decoding both
// families and skipping an entry it cannot express (AF_UNSPEC).
func TestDNSServerAddrsOfDecodesTheList(t *testing.T) {
	v4 := sockaddrIn(t, "10.0.0.1")
	v6 := sockaddrIn6(t, "2001:db8::53", 0)
	var unspec windows.RawSockaddrInet

	third := &windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{Sockaddr: rawAny(&unspec)}}
	second := &windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{Sockaddr: rawAny(&v6)}, Next: third}
	first := &windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{Sockaddr: rawAny(&v4)}, Next: second}
	aa := &windows.IpAdapterAddresses{FirstDnsServerAddress: first}

	got := dnsServerAddrsOf(aa)
	want := []string{"10.0.0.1", "2001:db8::53"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("dnsServerAddrsOf mismatch (-want +got):\n%s", diff)
	}
}

// TestDNSServerAddrsOfSkipsANilSockaddr: GetAdaptersAddresses' own docs do
// not promise every DNS server entry carries a non-nil Sockaddr, and
// dereferencing one that is nil would panic rather than simply skip an
// address this file cannot read anyway — the same tolerance
// TestUnicastAddrsOfSkipsANilSockaddr pins for the unicast list.
func TestDNSServerAddrsOfSkipsANilSockaddr(t *testing.T) {
	aa := &windows.IpAdapterAddresses{
		FirstDnsServerAddress: &windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{}},
	}
	if got := dnsServerAddrsOf(aa); len(got) != 0 {
		t.Errorf("dnsServerAddrsOf(nil Sockaddr) = %v, want none", got)
	}
}

// TestDNSServerAddrsOfEmptyList: an adapter with no DNS servers configured at
// all (FirstDnsServerAddress nil) must not panic walking a list that never
// starts.
func TestDNSServerAddrsOfEmptyList(t *testing.T) {
	if got := dnsServerAddrsOf(&windows.IpAdapterAddresses{}); got != nil {
		t.Errorf("dnsServerAddrsOf(empty) = %v, want nil", got)
	}
}

// TestDNSAdaptersAddressesFlagsKeepsDNSServerData is the regression guard on
// this file's whole reason for not reusing iface.go's adapterAddresses: if
// GAA_FLAG_SKIP_DNS_SERVER ever finds its way into dnsAdaptersAddressesFlags
// — a refactor that tries to "deduplicate" the two flag constants, say — this
// file goes back to reading an always-empty DNS server list, silently, on
// every real machine. It would still compile and still return successfully;
// it would just be wrong. See TestUnicastAddrsOfDecodesTheList and friends
// for why that class of bug does not fail loudly here.
func TestDNSAdaptersAddressesFlagsKeepsDNSServerData(t *testing.T) {
	if dnsAdaptersAddressesFlags&windows.GAA_FLAG_SKIP_DNS_SERVER != 0 {
		t.Error("dnsAdaptersAddressesFlags sets GAA_FLAG_SKIP_DNS_SERVER; this file would never see a DNS server again")
	}
	if dnsAdaptersAddressesFlags&windows.GAA_FLAG_SKIP_FRIENDLY_NAME != 0 {
		t.Error("dnsAdaptersAddressesFlags sets GAA_FLAG_SKIP_FRIENDLY_NAME; findAdapter matches on FriendlyName and would never match again")
	}
}
