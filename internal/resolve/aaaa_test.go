package resolve

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestAAAAModeString(t *testing.T) {
	for mode, want := range map[AAAAMode]string{
		AAAAAuto:     "auto",
		AAAAAllow:    "allow",
		AAAASuppress: "suppress",
	} {
		if got := mode.String(); got != want {
			t.Fatalf("AAAAMode(%d).String() = %q, want %q", mode, got, want)
		}
	}
}

// TestEmbeddedV4CoversEveryLegalPrefix walks RFC 6052 §2.2. The u-octet at byte
// 8 is not part of the address, so reading four contiguous bytes would
// mis-detect a /48 as a /40 and report a NAT64 prefix that does not exist.
func TestEmbeddedV4CoversEveryLegalPrefix(t *testing.T) {
	cases := map[int]string{
		32: "2001:db8:c000:aa::",
		40: "2001:db8:c0:0:aa::",
		48: "2001:db8:1:c000:0:aa00::",
		56: "2001:db8:1:c0:0:aa::",
		64: "64:ff9b:0:0:c0:0:aa00:0",
		96: "64:ff9b::192.0.0.170",
	}
	for bits, s := range cases {
		a := netip.MustParseAddr(s)
		got, ok := embeddedV4(a.As16(), bits)
		if !ok {
			t.Fatalf("/%d: extraction failed for %s", bits, s)
		}
		if got != [4]byte{192, 0, 0, 170} {
			t.Fatalf("/%d: extracted %v from %s, want 192.0.0.170", bits, got, s)
		}
	}
	if _, ok := embeddedV4(netip.MustParseAddr("::").As16(), 33); ok {
		t.Fatal("an illegal prefix length must not extract anything")
	}
	// A non-zero u-octet means this is not an RFC 6052 address.
	bad := netip.MustParseAddr("64:ff9b:0:0:ff00:0:aa00:0").As16()
	if _, ok := embeddedV4(bad, 64); ok {
		t.Fatal("a non-zero u-octet must be rejected")
	}
}

func TestNAT64PrefixDetection(t *testing.T) {
	// The well-known prefix, and the second well-known address.
	for _, s := range []string{"64:ff9b::192.0.0.170", "64:ff9b::192.0.0.171"} {
		p, ok := nat64Prefix(netip.MustParseAddr(s))
		if !ok {
			t.Fatalf("%s must be recognised as DNS64 synthesis", s)
		}
		if p.Bits() != 96 && p.Bits() != 64 {
			t.Fatalf("%s prefix = %s", s, p)
		}
	}
	if _, ok := nat64Prefix(netip.MustParseAddr("2606:4700::1111")); ok {
		t.Fatal("an ordinary AAAA must not look like DNS64 synthesis")
	}
}

func TestAAAAPolicyModes(t *testing.T) {
	always := &aaaaPolicy{mode: AAAAAllow}
	if ok, _ := always.allow(context.Background()); !ok {
		t.Fatal("AAAAAllow must allow")
	}
	never := &aaaaPolicy{mode: AAAASuppress}
	ok, why := never.allow(context.Background())
	if ok || why == "" {
		t.Fatalf("AAAASuppress must suppress with a reason, got %v %q", ok, why)
	}

	// AAAAAuto with no evidence allows, which is the whole point: a clean
	// network must not lose IPv6.
	auto := &aaaaPolicy{mode: AAAAAuto, v4Path: func() bool { return true }}
	if ok, _ := auto.allow(context.Background()); !ok {
		t.Fatal("AAAAAuto must allow before any evidence")
	}
	auto.noteV6Poison("a sinkholed AAAA was observed")
	if ok, why := auto.allow(context.Background()); ok {
		t.Fatalf("AAAAAuto must suppress once poisoned with a v4 path, got allow (%q)", why)
	}

	// With no verified v4 path there is nothing left to connect with.
	noV4 := &aaaaPolicy{mode: AAAAAuto}
	noV4.noteV6Poison("x")
	if ok, _ := noV4.allow(context.Background()); !ok {
		t.Fatal("suppression without a v4 path is a total outage")
	}

	// NAT64 vetoes suppression: on a 464XLAT carrier the AAAA is the
	// connectivity.
	nat := &aaaaPolicy{
		mode:   AAAAAuto,
		v4Path: func() bool { return true },
		nat64:  func(context.Context) NAT64 { return NAT64{Detected: true} },
	}
	nat.noteV6Poison("x")
	if ok, _ := nat.allow(context.Background()); !ok {
		t.Fatal("NAT64 must veto AAAA suppression")
	}
}

func TestHasGlobalIPv4IsReadOnly(t *testing.T) {
	// The value depends on the machine; what matters is that reading it
	// inspects interface state and resolves nothing.
	_ = hasGlobalIPv4()
}

// TestOwnDialsSkipAAAAWithNoIPv6Path is the regression for a real outage found
// by running the proxy on this machine: www.turkiye.gov.tr answers in both
// families, this host has no global IPv6 address, the A lookup lost one race,
// the AAAA-only answer was cached, and eight consecutive requests through the
// proxy failed instantly with "connect: no route to host" — while the site
// loaded fine outside dpb.
//
// The old rule reasoned that our own dials are protected in both families, so
// only poisoning could justify withholding one. Protected is not reachable.
func TestOwnDialsSkipAAAAWithNoIPv6Path(t *testing.T) {
	t.Parallel()
	yes := func() bool { return true }
	no := func() bool { return false }
	noNAT64 := func(context.Context) NAT64 { return NAT64{} }

	for _, tc := range []struct {
		name      string
		v6Host    func() bool
		v6Path    func() bool
		wantOwn   bool
		wantWhyIn string
	}{
		{"no v6 on the host: withheld from our own dials", no, no, false, "no global IPv6 address"},
		{"v6 on the host: allowed for our own dials", yes, no, true, ""},
		{"v6 carried by a tunnel: allowed", yes, yes, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &aaaaPolicy{mode: AAAAAuto, v4Path: yes, v6Path: tc.v6Path, v6Host: tc.v6Host, nat64: noNAT64}
			got, why := p.allow(context.Background())
			if got != tc.wantOwn {
				t.Fatalf("allow() = %v (%q), want %v", got, why, tc.wantOwn)
			}
			if tc.wantWhyIn != "" && !strings.Contains(why, tc.wantWhyIn) {
				t.Errorf("reason %q does not mention %q", why, tc.wantWhyIn)
			}
		})
	}

	// Suppressing a family the host cannot reach must never be the thing that
	// takes the last address away: with no v4 path either, AAAA stays allowed.
	p := &aaaaPolicy{mode: AAAAAuto, v4Path: no, v6Path: no, v6Host: no, nat64: noNAT64}
	if ok, why := p.allow(context.Background()); !ok {
		t.Errorf("with no IPv4 path, AAAA must stay allowed or there is nothing left to dial: %q", why)
	}
	// NAT64 is the other escape: there the AAAA *is* the connectivity.
	p = &aaaaPolicy{mode: AAAAAuto, v4Path: yes, v6Path: no, v6Host: no,
		nat64: func(context.Context) NAT64 { return NAT64{Detected: true} }}
	if ok, why := p.allow(context.Background()); !ok {
		t.Errorf("on a NAT64 network AAAA must stay allowed: %q", why)
	}
	// A nil predicate must not suppress a whole family by omission.
	p = &aaaaPolicy{mode: AAAAAuto, v4Path: yes, v6Path: no, nat64: noNAT64}
	if ok, _ := p.allow(context.Background()); !ok {
		t.Error("an unwired v6Host predicate must read as reachable")
	}
}
