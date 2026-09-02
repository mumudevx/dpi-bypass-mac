package policy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestIPSetMatchesMostSpecificFirst(t *testing.T) {
	s, err := NewIPSet([]Rule{
		{Pattern: "10.0.0.0/8", Class: ScopeBypass, From: "cfg", Line: 1},
		{Pattern: "10.1.0.0/16", Class: ScopeDirect, From: "cfg", Line: 2},
		{Pattern: "10.1.2.3", Class: ScopeWatch, From: "cfg", Line: 3},
		{Pattern: "2001:db8::/32", Class: ScopeBypass, From: "cfg", Line: 4},
	})
	if err != nil {
		t.Fatalf("NewIPSet: %v", err)
	}
	got := patterns(s.Match(netip.MustParseAddr("10.1.2.3")))
	want := []string{"10.1.2.3", "10.1.0.0/16", "10.0.0.0/8"}
	if !equalStrings(got, want) {
		t.Errorf("Match(10.1.2.3) = %v, want %v", got, want)
	}
	if got := patterns(s.Match(netip.MustParseAddr("10.9.9.9"))); !equalStrings(got, []string{"10.0.0.0/8"}) {
		t.Errorf("Match(10.9.9.9) = %v", got)
	}
	if s.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Error("11.0.0.1 matched a 10/8 rule")
	}
	if !s.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("2001:db8::1 did not match its /32")
	}
	if s.Len() != 4 {
		t.Errorf("Len = %d, want 4", s.Len())
	}
	if got := s.Match(netip.Addr{}); got != nil {
		t.Errorf("invalid address matched %v", patterns(got))
	}
}

// A rule written unmasked must behave like the masked prefix; netip.Prefix
// Contains reports false for an unmasked prefix, which would silently disable
// the rule.
func TestParsePrefixMasksAndAcceptsBareAddresses(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.1.2.3/8", "10.0.0.0/8"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"1.2.3.4", "1.2.3.4/32"},
		{" ::1 ", "::1/128"},
		{"::ffff:10.0.0.1", "10.0.0.1/32"},
	}
	for _, c := range cases {
		p, err := ParsePrefix(c.in)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", c.in, err)
		}
		if p.String() != c.want {
			t.Errorf("ParsePrefix(%q) = %s, want %s", c.in, p, c.want)
		}
	}
	for _, bad := range []string{"", "   ", "not-an-address", "example.com", "10.0.0.0/99"} {
		if _, err := ParsePrefix(bad); err == nil {
			t.Errorf("ParsePrefix(%q) succeeded", bad)
		}
	}
	if _, err := NewIPSet([]Rule{{Pattern: "nope", From: "cfg", Line: 7}}); err == nil ||
		!strings.Contains(err.Error(), "cfg:7") {
		t.Errorf("NewIPSet error = %v, want one carrying provenance", err)
	}
}

// The bogon table is a hard veto and must survive both construction and a
// reload that supplies no address rules at all.
func TestBogons(t *testing.T) {
	inside := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.0.1",
		"100.64.0.1", "169.254.1.1", "fe80::1", "fc00::1", "ff02::1",
		"224.0.0.1", "198.18.0.1", "0.0.0.0", "255.255.255.255",
		"::ffff:192.168.1.1", // 4-in-6 must not sidestep the RFC1918 veto
	}
	for _, s := range inside {
		if !IsBogon(netip.MustParseAddr(s)) {
			t.Errorf("IsBogon(%s) = false, want true", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "162.159.128.233", "2606:4700::1", "195.175.254.2"} {
		if IsBogon(netip.MustParseAddr(s)) {
			t.Errorf("IsBogon(%s) = true, want false", s)
		}
	}
	if IsBogon(netip.Addr{}) {
		t.Error("IsBogon(invalid) = true")
	}
	if len(BogonPrefixes()) != len(bogonPrefixes) {
		t.Error("BogonPrefixes did not copy the table")
	}

	var nilSet *IPSet
	withBogons := nilSet.WithBogons()
	if !withBogons.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Error("WithBogons on a nil set lost the RFC1918 veto")
	}
	if nilSet.Len() != 0 || nilSet.Match(netip.MustParseAddr("1.1.1.1")) != nil {
		t.Error("nil IPSet is not inert")
	}
}

// A zoned link-local address is the one case netip.Prefix silently refuses to
// match, so the canonical form has to strip the zone before any lookup.
func TestZonedAddressStillHitsTheLinkLocalVeto(t *testing.T) {
	zoned := netip.MustParseAddr("fe80::1%en0")
	if !IsBogon(zoned) {
		t.Fatal("a zoned fe80 address was not recognised as link-local")
	}
	s := (*IPSet)(nil).WithBogons()
	if !s.Contains(zoned) {
		t.Fatal("zoned link-local address missed every bogon rule")
	}
	if got := Normalize("fe80::1%en0"); got != "fe80::1" {
		t.Errorf("Normalize of a zoned address = %q, want fe80::1", got)
	}
}
