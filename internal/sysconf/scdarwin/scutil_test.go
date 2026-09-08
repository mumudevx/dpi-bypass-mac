package scdarwin

import (
	"context"
	"reflect"
	"testing"
)

// scutilProxyPACOn is synthesised, not captured: enabling a system PAC would
// mutate the developer's machine, which this test suite is not allowed to do.
// The key names and the "0"/"1" boolean encoding are taken verbatim from the
// captured testdata/scutil_proxy.txt.
const scutilProxyPACOn = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 8080
  HTTPSProxy : 127.0.0.1
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://127.0.0.1:8080/dpb.pac
  SOCKSEnable : 1
  SOCKSPort : 1080
  SOCKSProxy : 127.0.0.1
}`

func TestParseProxyStateCaptured(t *testing.T) {
	st := parseProxyState(fixture(t, "scutil_proxy.txt"))
	if st.On("ProxyAutoConfigEnable") {
		t.Fatal("captured state has no PAC configured, but On() reported one")
	}
	if st.On("HTTPEnable") || st.On("HTTPSEnable") || st.On("SOCKSEnable") {
		t.Fatal("captured state has every proxy disabled")
	}
	if got := st.Str("FTPPassive"); got != "1" {
		t.Fatalf("FTPPassive = %q, want 1", got)
	}
	want := []string{"*.local", "169.254/16"}
	if !reflect.DeepEqual(st.Exceptions, want) {
		t.Fatalf("Exceptions = %v, want %v", st.Exceptions, want)
	}
	// A key inside the nested array must not leak into the flat map.
	if _, ok := st.Keys["0"]; ok {
		t.Fatal("array entries leaked into the key map")
	}
}

func TestParseProxyStateEnabled(t *testing.T) {
	st := parseProxyState(scutilProxyPACOn)
	if !st.On("ProxyAutoConfigEnable") {
		t.Fatal("PAC should be enabled")
	}
	if got := st.Str("ProxyAutoConfigURLString"); got != "http://127.0.0.1:8080/dpb.pac" {
		t.Fatalf("PAC URL = %q", got)
	}
	if got, ok := st.Int("HTTPPort"); !ok || got != 8080 {
		t.Fatalf("HTTPPort = %d ok=%v", got, ok)
	}
	if _, ok := st.Int("NoSuchKey"); ok {
		t.Fatal("Int on a missing key must report ok=false")
	}
}

// The checkProxyPair half of this test stayed in netstate, as
// TestCheckProxyPair: deciding whether a ProxyState satisfies a request is a
// policy netstate makes and this package only supplies the state to make it
// against. Every assertion on either side is the one it always was.

func TestParseDNSResolversCaptured(t *testing.T) {
	rs := parseDNSResolvers(fixture(t, "scutil_dns.txt"))
	if len(rs) < 2 {
		t.Fatalf("parsed %d resolvers, want several", len(rs))
	}
	first := rs[0]
	if first.Index != 1 {
		t.Fatalf("first resolver index = %d", first.Index)
	}
	if len(first.Nameservers) == 0 {
		t.Fatal("first resolver has no nameservers")
	}
	if first.IfName != "en0" || first.IfIndex != 14 {
		t.Fatalf("if_index parsed as %d (%s), want 14 (en0)", first.IfIndex, first.IfName)
	}
	if first.Scoped {
		t.Fatal("the first resolver is not in the scoped section")
	}

	sawScoped := false
	for _, r := range rs {
		if r.Scoped {
			sawScoped = true
		}
	}
	if !sawScoped {
		t.Fatal("the scoped-queries section was not recognised")
	}

	ns := primaryNameservers(rs)
	if len(ns) == 0 || ns[0] != first.Nameservers[0] {
		t.Fatalf("primaryNameservers = %v, want it to start with %v", ns, first.Nameservers)
	}
}

func TestPrimaryNameserversSkipsMDNSDomains(t *testing.T) {
	rs := []DNSResolver{
		{Index: 1, Domain: "local", Nameservers: []string{"224.0.0.251"}},
		{Index: 2, Nameservers: []string{"127.0.0.1", "192.168.0.1"}},
		{Index: 1, Scoped: true, Nameservers: []string{"9.9.9.9"}},
	}
	got := primaryNameservers(rs)
	want := []string{"127.0.0.1", "192.168.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("primaryNameservers = %v, want %v", got, want)
	}
	if got := primaryNameservers(nil); got != nil {
		t.Fatalf("primaryNameservers(nil) = %v", got)
	}
}

func TestParseNCList(t *testing.T) {
	if got := parseNCList(fixture(t, "scutil_nc_empty.txt")); len(got) != 0 {
		t.Fatalf("captured empty VPN list parsed as %v", got)
	}
	out := "Available network connection services in the current set (*=enabled):\n" +
		"* (Connected) 8F6A1B2C-0000-0000-0000-000000000001 PPP (L2TP) \"Work VPN\" [PPP:L2TP]\n" +
		"  (Disconnected) 8F6A1B2C-0000-0000-0000-000000000002 IPSec \"Corp\" [IPSec]\n"
	got := parseNCList(out)
	if len(got) != 2 {
		t.Fatalf("parsed %d services, want 2: %+v", len(got), got)
	}
	if !got[0].Enabled || !got[0].Connected() || got[0].Name != "Work VPN" {
		t.Fatalf("first service parsed as %+v", got[0])
	}
	if got[1].Enabled || got[1].Connected() || got[1].Name != "Corp" {
		t.Fatalf("second service parsed as %+v", got[1])
	}
}

func TestReadersSurfaceCommandFailure(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	f.failNext("scutil --proxy", 1)
	if _, err := readProxyState(context.Background(), e); err == nil {
		t.Fatal("readProxyState swallowed a command failure")
	}
	f.failNext("scutil --dns", 1)
	if _, err := readDNSResolvers(context.Background(), e); err == nil {
		t.Fatal("readDNSResolvers swallowed a command failure")
	}
	f.failNext("scutil --nc list", 1)
	if _, err := readNCList(context.Background(), e); err == nil {
		t.Fatal("readNCList swallowed a command failure")
	}
}

// TestParseDNSServersOutput came from netstate's ops_test.go with
// parseDNSServers: `networksetup -getdnsservers` prints one address per line,
// or a sentence when there are none, and reading that sentence correctly is a
// property of the tool's output rather than of the Op that calls it.
func TestParseDNSServersOutput(t *testing.T) {
	if got := parseDNSServers(fixture(t, "networksetup_dns_none.txt")); len(got) != 0 {
		t.Fatalf("parsed %v from the 'no servers' sentence", got)
	}
	if got := parseDNSServers("1.1.1.1\n8.8.8.8\n"); !reflect.DeepEqual(got, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("parsed %v", got)
	}
}
