//go:build windows

package scwindows

import (
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

// capturedRouteFrom and capturedAdapterFrom are pure — no syscall — so they
// are pinned with hand-built rows the same way rib.go's routeEntryFrom and
// iface.go's unicastAddrsOf already are, using the same sockaddrIn / sockaddrIn6
// / utf16Ptr / rawAny helpers those tests declare (rib_test.go, route_test.go,
// iface_test.go). The three capture functions that actually call
// GetIpForwardTable2, GetAdaptersAddresses and
// WinHttpGetIEProxyConfigForCurrentUser are exercised for real further down:
// this branch's windows-latest CI job is a real Windows machine, unlike the
// rest of this package's tests, which predate that job and still say so in
// their own comments.

func TestCapturedRouteFromDecodesFields(t *testing.T) {
	names := map[int]string{5: "Wi-Fi"}
	r := windows.MibIpForwardRow2{
		InterfaceIndex: 5,
		Metric:         256,
		Protocol:       3, // MIB_IPPROTO_NETMGMT
		Origin:         1, // NlroManual
	}
	r.DestinationPrefix.Prefix = sockaddrIn(t, "0.0.0.0")
	r.DestinationPrefix.PrefixLength = 0
	r.NextHop = sockaddrIn(t, "192.168.1.1")

	got := capturedRouteFrom(&r, names)
	want := CapturedRoute{
		Destination:    "0.0.0.0/0",
		NextHop:        "192.168.1.1",
		InterfaceIndex: 5,
		InterfaceName:  "Wi-Fi",
		Metric:         256,
		Protocol:       3,
		Origin:         1,
	}
	if got != want {
		t.Errorf("capturedRouteFrom mismatch\n got %+v\nwant %+v", got, want)
	}
}

// TestCapturedRouteFromOnLinkHasNoNextHop pins the same reading rib.go's
// routeEntryFrom gives an unspecified next hop: it is not a gateway, so it is
// recorded as absent rather than as "0.0.0.0", which would read as a real
// gateway address to anything that later parses the fixture.
func TestCapturedRouteFromOnLinkHasNoNextHop(t *testing.T) {
	r := windows.MibIpForwardRow2{InterfaceIndex: 17}
	r.DestinationPrefix.Prefix = sockaddrIn(t, "10.1.2.3")
	r.DestinationPrefix.PrefixLength = 8
	r.NextHop = sockaddrIn(t, "0.0.0.0")

	got := capturedRouteFrom(&r, map[int]string{})
	if got.NextHop != "" {
		t.Errorf("NextHop = %q, want empty for an unspecified next hop", got.NextHop)
	}
	// The table stores masked prefixes; a capture that echoed host bits back
	// would misdescribe what GetIpForwardTable2 actually returned.
	if got.Destination != "10.0.0.0/8" {
		t.Errorf("Destination = %q, want the masked prefix", got.Destination)
	}
}

// TestCapturedRouteFromKeepsAnUnreadableRow: routeEntryFrom drops a row whose
// destination family it cannot express (see rib.go). A capture must not drop
// it the same way — the row still came back from the table, and silently
// shrinking the count would misreport how many rows GetIpForwardTable2
// returned — so Destination is left blank instead.
func TestCapturedRouteFromKeepsAnUnreadableRow(t *testing.T) {
	var r windows.MibIpForwardRow2 // AF_UNSPEC destination and next hop
	got := capturedRouteFrom(&r, map[int]string{})
	if got.Destination != "" {
		t.Errorf("Destination = %q, want empty for an AF_UNSPEC row", got.Destination)
	}
	if got.NextHop != "" {
		t.Errorf("NextHop = %q, want empty for an AF_UNSPEC row", got.NextHop)
	}
}

func TestCapturedAdapterFromDecodesFields(t *testing.T) {
	v4 := sockaddrIn(t, "10.255.0.1")
	ua := &windows.IpAdapterUnicastAddress{Address: windows.SocketAddress{Sockaddr: rawAny(&v4)}}
	aa := &windows.IpAdapterAddresses{
		FriendlyName:        utf16Ptr(t, "Wi-Fi"),
		Description:         utf16Ptr(t, "Example Wi-Fi Adapter"),
		IfIndex:             5,
		IfType:              71, // IF_TYPE_IEEE80211
		OperStatus:          1,  // IfOperStatusUp
		Mtu:                 1500,
		FirstUnicastAddress: ua,
	}

	got := capturedAdapterFrom(aa)
	want := CapturedAdapter{
		FriendlyName:     "Wi-Fi",
		Description:      "Example Wi-Fi Adapter",
		IfIndex:          5,
		IfType:           71,
		OperStatus:       1,
		Mtu:              1500,
		UnicastAddresses: []string{"10.255.0.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("capturedAdapterFrom mismatch\n got %+v\nwant %+v", got, want)
	}
}

// TestCapturedAdapterFromNoAddressesIsNilNotEmpty matches
// json.Marshal's own "omitempty" contract: a nil slice and an empty one both
// marshal as "no addresses reported", but only nil is what an adapter with
// FirstUnicastAddress == nil should ever produce.
func TestCapturedAdapterFromNoAddressesIsNilNotEmpty(t *testing.T) {
	aa := &windows.IpAdapterAddresses{FriendlyName: utf16Ptr(t, "lo")}
	got := capturedAdapterFrom(aa)
	if got.UnicastAddresses != nil {
		t.Errorf("UnicastAddresses = %v, want nil for an adapter with none", got.UnicastAddresses)
	}
}

// TestCaptureRoutesOnThisMachine exercises the real GetIpForwardTable2 call.
// rib.go's own Routes comment states the property this relies on: a machine
// dpb runs on always has routes, so this is not asserting anything about the
// runner's specific network configuration, only that the call succeeds and
// returns something — true of a GitHub-hosted windows-latest runner exactly
// as it is true of a laptop.
func TestCaptureRoutesOnThisMachine(t *testing.T) {
	routes, err := CaptureRoutes()
	if err != nil {
		t.Fatalf("CaptureRoutes: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("CaptureRoutes returned no rows; every real machine has at least one")
	}
	if _, err := json.Marshal(routes); err != nil {
		t.Errorf("[]CapturedRoute does not marshal to JSON: %v", err)
	}
}

// TestCaptureAdaptersOnThisMachine exercises the real GetAdaptersAddresses
// call. Unlike routes, an adapter list can legitimately be reported empty by
// the flags this package requests (adaptersAddressesFlags skips several
// categories), so only the call succeeding and marshalling cleanly is
// asserted.
func TestCaptureAdaptersOnThisMachine(t *testing.T) {
	adapters, err := CaptureAdapters()
	if err != nil {
		t.Fatalf("CaptureAdapters: %v", err)
	}
	if _, err := json.Marshal(adapters); err != nil {
		t.Errorf("[]CapturedAdapter does not marshal to JSON: %v", err)
	}
}

// TestCaptureProxyConfigNeverErrors exercises the real
// WinHttpGetIEProxyConfigForCurrentUser call. It deliberately does not assert
// Available: a GitHub-hosted runner's account has never had Internet Explorer
// proxy settings touched, and proxy.go's own liveFromWinHTTP comment names
// exactly that case (ERROR_FILE_NOT_FOUND, "no IE configuration for the
// token") as expected, not exceptional. What must hold on every machine is
// the contract CapturedProxyConfig's own doc comment states: unavailable
// always says why, and the result always marshals.
func TestCaptureProxyConfigNeverErrors(t *testing.T) {
	got := CaptureProxyConfig()
	if !got.Available && got.Error == "" {
		t.Error("an unavailable capture must say why")
	}
	if _, err := json.Marshal(got); err != nil {
		t.Errorf("CapturedProxyConfig does not marshal to JSON: %v", err)
	}
}

// TestRedactAddrStringKeepsCategoryAndLength pins capture.go's redaction
// policy field by field, because the policy is the whole privacy guarantee:
// what a fixture keeps is the category and the prefix length, what it loses is
// which network. A row that came back unchanged from here would be a row that
// names the machine the capture was taken on.
func TestRedactAddrStringKeepsCategoryAndLength(t *testing.T) {
	for _, c := range []struct {
		in, want, why string
	}{
		{"0.0.0.0/0", "0.0.0.0/0", "the default route is a constant, not an identity"},
		{"::/0", "::/0", "the same, for v6"},
		{"127.0.0.0/8", "127.0.0.0/8", "loopback is a constant"},
		{"::1", "::1", "loopback is a constant"},
		{"192.168.1.0/24", "198.51.100.0/24", "an RFC 1918 LAN prefix keeps its length"},
		{"10.0.0.0/8", "198.0.0.0/8", "a /8 stand-in is masked to its /8"},
		{"192.168.1.1", "198.51.100.0", "a gateway address loses its identity"},
		{"203.0.113.9", "198.51.100.0", "so does a public one"},
		{"100.64.0.1", "198.51.100.0", "and a CGNAT one"},
		{"169.254.1.2", "169.254.0.0", "link-local keeps its category"},
		{"fe80::1234:5678:9abc:def0", "fe80::", "an EUI-64 interface id is device identity"},
		{"fd12:3456:789a::1", "2001:db8::", "a ULA /48 is generated per site"},
		{"2a01:358:4014:a00::3", "2001:db8::", "a global v6 address is an ISP allocation"},
		{"224.0.0.251", "224.0.0.0", "multicast keeps its category"},
		{"ff02::fb", "ff00::", "so does v6 multicast"},
		{"", "", "an unreadable row's empty destination stays empty"},
		{"not an address", "redacted", "a value that cannot be classified is not passed through"},
	} {
		if got := redactAddrString(c.in); got != c.want {
			t.Errorf("redactAddrString(%q) = %q, want %q (%s)", c.in, got, c.want, c.why)
		}
	}
}

// TestRedactedProxyConfigDropsEveryStringAndNamesIt: the PAC URL is the field
// this redaction exists for — on a managed laptop it names the employer — so
// what must hold is that no part of it survives while the FACT that it was set
// does, which is the part a test could ever want.
func TestRedactedProxyConfigDropsEveryStringAndNamesIt(t *testing.T) {
	got := CapturedProxyConfig{
		Available:     true,
		AutoDetect:    true,
		AutoConfigURL: "http://wpad.corp.example/proxy.pac",
		Proxy:         "http=proxy.corp.example:8080",
		ProxyBypass:   "*.corp.example;<local>",
	}.redacted()

	if got.AutoConfigURL != "" || got.Proxy != "" || got.ProxyBypass != "" {
		t.Errorf("a redacted capture still carries a proxy string: %+v", got)
	}
	if !got.Available || !got.AutoDetect {
		t.Errorf("redaction must keep the non-identifying fields: %+v", got)
	}
	want := []string{"auto_config_url", "proxy", "proxy_bypass"}
	if !reflect.DeepEqual(got.Redacted, want) {
		t.Errorf("Redacted = %v, want %v", got.Redacted, want)
	}

	// A machine with nothing configured says so by naming nothing, rather than
	// by naming fields that were empty anyway.
	clean := CapturedProxyConfig{Available: true}.redacted()
	if clean.Redacted != nil {
		t.Errorf("Redacted = %v, want nil when no string was set", clean.Redacted)
	}
}

// TestCaptureProxyConfigOnThisMachineIsRedacted closes the loop on the real
// call: whatever WinHttpGetIEProxyConfigForCurrentUser returned on this
// machine, what leaves the package carries no proxy string. On a CI runner
// every string is empty anyway and this proves little; on a developer's
// managed laptop it is the assertion that matters, and it is the same code
// path in both places.
func TestCaptureProxyConfigOnThisMachineIsRedacted(t *testing.T) {
	got := CaptureProxyConfig()
	if got.AutoConfigURL != "" || got.Proxy != "" || got.ProxyBypass != "" {
		t.Errorf("CaptureProxyConfig returned an unredacted string: %+v", got)
	}
}

// TestCaptureRoutesOnThisMachineIsRedacted: every destination and next hop
// that left the package has to be a value redactAddrString can produce, which
// is what "no row names this machine's network" means operationally. A real
// table always has rows redaction touches (a default route's next hop, an
// on-link LAN prefix), so this is not vacuous on any machine that has a
// network — including the runner.
func TestCaptureRoutesOnThisMachineIsRedacted(t *testing.T) {
	routes, err := CaptureRoutes()
	if err != nil {
		t.Fatalf("CaptureRoutes: %v", err)
	}
	for _, r := range routes {
		if got := redactAddrString(r.Destination); got != r.Destination {
			t.Errorf("destination %q is not redacted (redacting it again gives %q)", r.Destination, got)
		}
		if got := redactAddrString(r.NextHop); got != r.NextHop {
			t.Errorf("next hop %q is not redacted (redacting it again gives %q)", r.NextHop, got)
		}
	}
}

// TestCaptureAdaptersOnThisMachineIsRedacted is the same assertion for the
// unicast addresses, which are the adapter fields that name a network.
func TestCaptureAdaptersOnThisMachineIsRedacted(t *testing.T) {
	adapters, err := CaptureAdapters()
	if err != nil {
		t.Fatalf("CaptureAdapters: %v", err)
	}
	for _, a := range adapters {
		for _, addr := range a.UnicastAddresses {
			if got := redactAddrString(addr); got != addr {
				t.Errorf("adapter %q address %q is not redacted (got %q)", a.FriendlyName, addr, got)
			}
		}
	}
}
