package policy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNetworkIDKeyIsStableAndDiscriminating(t *testing.T) {
	home := NetworkID{
		Kind:        "wifi",
		SSID:        "ev",
		Gateway:     netip.MustParseAddr("192.168.0.1"),
		GatewayMAC:  "AA:BB:CC:DD:EE:FF",
		ResolverSet: ResolverSetHash([]string{"192.168.0.1"}),
	}
	if home.Key() != home.Key() {
		t.Fatal("Key is not deterministic")
	}
	if !strings.HasPrefix(home.Key(), "wifi-") {
		t.Errorf("Key = %q, want a readable kind prefix", home.Key())
	}
	if home.Key() != home.String() {
		t.Error("String must be the Key")
	}

	// Cosmetic differences must not split the cache; a reconnect that reports
	// the MAC in a different case would otherwise lose every learned verdict.
	same := home
	same.GatewayMAC = "aa:bb:cc:dd:ee:ff"
	same.Kind = "WiFi"
	if !home.Equal(same) {
		t.Error("case differences produced a different NetworkID")
	}

	// Every field is discriminating: a hotspot with the same gateway address
	// but a different SSID is a different censor.
	for name, mutate := range map[string]func(*NetworkID){
		"kind":     func(n *NetworkID) { n.Kind = "cellular" },
		"ssid":     func(n *NetworkID) { n.SSID = "cafe" },
		"gateway":  func(n *NetworkID) { n.Gateway = netip.MustParseAddr("10.0.0.1") },
		"mac":      func(n *NetworkID) { n.GatewayMAC = "11:22:33:44:55:66" },
		"resolver": func(n *NetworkID) { n.ResolverSet = ResolverSetHash([]string{"8.8.8.8"}) },
	} {
		other := home
		mutate(&other)
		if home.Equal(other) {
			t.Errorf("changing %s did not change the NetworkID", name)
		}
	}
}

func TestNetworkIDZeroValue(t *testing.T) {
	var zero NetworkID
	if !zero.IsZero() {
		t.Error("zero value is not IsZero")
	}
	if !strings.HasPrefix(zero.Key(), "unknown-") {
		t.Errorf("zero Key = %q, want an unknown- prefix", zero.Key())
	}
	if (NetworkID{Kind: "wifi"}).IsZero() {
		t.Error("a populated Kind still reported IsZero")
	}
	// The key must remain a safe single path segment / JSON key whatever the
	// collector hands us.
	weird := NetworkID{Kind: "../../etc passwd\n"}
	k := weird.Key()
	if strings.ContainsAny(k, "/. \n") {
		t.Errorf("Key = %q, want a sanitised segment", k)
	}
	if len(strings.SplitN(k, "-", 2)[0]) > 16 {
		t.Errorf("Key prefix in %q is not bounded", k)
	}
}

func TestResolverSetHash(t *testing.T) {
	a := ResolverSetHash([]string{"8.8.8.8", "1.1.1.1"})
	b := ResolverSetHash([]string{" 1.1.1.1 ", "8.8.8.8", "8.8.8.8", ""})
	if a != b {
		t.Errorf("order, spacing and duplicates changed the hash: %q vs %q", a, b)
	}
	if ResolverSetHash(nil) != "" {
		t.Error("an empty resolver set must hash to the empty string")
	}
	if a == ResolverSetHash([]string{"195.175.254.2"}) {
		t.Error("different resolver sets collided")
	}
	// 4-in-6 spellings of the same resolver are the same resolver.
	if ResolverSetHash([]string{"::ffff:8.8.8.8"}) != ResolverSetHash([]string{"8.8.8.8"}) {
		t.Error("4-in-6 resolver spelling changed the hash")
	}
}
