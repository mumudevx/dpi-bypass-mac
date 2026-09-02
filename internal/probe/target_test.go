package probe_test

import (
	"net/netip"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
)

func TestTargetDialPortAndPin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		target     probe.Target
		wantPort   int
		wantPinned string
		wantString string
	}{
		{
			name:       "pinned, default port",
			target:     probe.Target{Host: "discord.com", Addr: "162.159.128.233"},
			wantPort:   443,
			wantPinned: "162.159.128.233",
			wantString: "discord.com:443[162.159.128.233]",
		},
		{
			name:       "explicit port, no pin",
			target:     probe.Target{Host: "discord.com", Port: 80},
			wantPort:   80,
			wantString: "discord.com:80",
		},
		{
			name:       "v4-mapped v6 pin is unmapped",
			target:     probe.Target{Host: "discord.com", Addr: "::ffff:162.159.128.233"},
			wantPort:   443,
			wantPinned: "162.159.128.233",
			wantString: "discord.com:443[::ffff:162.159.128.233]",
		},
		{
			name:       "unparseable pin is not a pin",
			target:     probe.Target{Host: "discord.com", Addr: "nonsense"},
			wantPort:   443,
			wantString: "discord.com:443[nonsense]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.target.DialPort(); got != tc.wantPort {
				t.Errorf("DialPort() = %d, want %d", got, tc.wantPort)
			}
			got, ok := tc.target.Pinned()
			if ok != (tc.wantPinned != "") {
				t.Fatalf("Pinned() ok = %v, want %v", ok, tc.wantPinned != "")
			}
			if ok && got.String() != tc.wantPinned {
				t.Errorf("Pinned() = %s, want %s", got, tc.wantPinned)
			}
			if s := tc.target.String(); s != tc.wantString {
				t.Errorf("String() = %q, want %q", s, tc.wantString)
			}
		})
	}
}

// The hostname survives pinning. MEASUREMENTS.md §1's experiment is exactly
// this separation — same IP, same port, only the SNI differs — so a pinned
// target that dropped its name would measure nothing.
func TestFlowTargetKeepsTheNameAndPinsTheAddress(t *testing.T) {
	t.Parallel()

	ft := probe.Target{Host: "discord.com", Addr: "162.159.128.233"}.Flow()
	if ft.Name != "discord.com" {
		t.Errorf("Name = %q, want discord.com", ft.Name)
	}
	want := netip.MustParseAddrPort("162.159.128.233:443")
	if ft.Addr != want {
		t.Errorf("Addr = %s, want %s", ft.Addr, want)
	}
	if ft.Port != 443 {
		t.Errorf("Port = %d, want 443", ft.Port)
	}

	unpinned := probe.Target{Host: "discord.com", Port: 8443}.Flow()
	if unpinned.Addr.IsValid() {
		t.Errorf("an unpinned target must carry no address, got %s", unpinned.Addr)
	}
	if unpinned.Port != 8443 {
		t.Errorf("Port = %d, want 8443", unpinned.Port)
	}
}

func TestTargetValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		target  probe.Target
		wantErr bool
	}{
		{"ok pinned", probe.Target{Host: "discord.com", Addr: "162.159.128.233"}, false},
		{"ok unpinned", probe.Target{Host: "discord.com"}, false},
		{"no host", probe.Target{Addr: "1.1.1.1"}, true},
		{"port too high", probe.Target{Host: "discord.com", Port: 65536}, true},
		{"negative port", probe.Target{Host: "discord.com", Port: -1}, true},
		{"pin is a hostname", probe.Target{Host: "discord.com", Addr: "discord.com"}, true},
	}
	for _, tc := range cases {
		err := tc.target.Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: Validate() = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
		if tc.wantErr && err != nil && !containsHostOrPort(err.Error()) {
			t.Errorf("%s: error %q must name what is wrong", tc.name, err)
		}
	}
}

func containsHostOrPort(s string) bool {
	for _, want := range []string{"host", "port", "address"} {
		if len(s) >= len(want) && indexOf(s, want) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestTargetKindNames(t *testing.T) {
	t.Parallel()
	want := map[probe.TargetKind]string{
		probe.TargetBlocked: "blocked",
		probe.TargetControl: "control",
		probe.TargetFragile: "fragile",
	}
	for k, s := range want {
		if got := k.String(); got != s {
			t.Errorf("TargetKind(%d) = %q, want %q", k, got, s)
		}
	}
	if got := probe.TargetKind(9).String(); got != "invalid" {
		t.Errorf("out-of-range kind = %q, want invalid", got)
	}
}
