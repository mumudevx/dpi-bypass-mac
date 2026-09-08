//go:build windows

package emit

import (
	"testing"

	"github.com/mumudevx/dpb/internal/strategy"
)

// The Turkey ladder's last rung is oob:pos=1 and its TTL rungs need IP_TTL.
// If either capability is withheld on Windows, a strategy that measured as
// working is silently downgraded — the exact failure stub_other.go's comment
// warns about.
func TestWindowsGrantsTheLadderCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  strategy.Cap
		want strategy.Cap
	}{
		{"sockTTL", sockTTLCaps, strategy.CapSockTTL},
		{"udpTTL", sockTTLCaps, strategy.CapUDPTTL},
		{"oob", oobCaps, strategy.CapOOB},
	} {
		if !tc.got.Has(tc.want) {
			t.Errorf("%s: caps %v lack %v", tc.name, tc.got, tc.want)
		}
	}
}

// A hardcoded 64 is what DOSSIER §3 warns against, and Windows defaults to 128
// rather than 64 — so a guess here is wrong on every Windows machine.
func TestWindowsDefaultTTLIsRead(t *testing.T) {
	n, err := DefaultTTL()
	if err != nil {
		t.Fatalf("DefaultTTL() error = %v", err)
	}
	if n <= 0 || n > 255 {
		t.Errorf("DefaultTTL() = %d, want a plausible hop limit", n)
	}
}
