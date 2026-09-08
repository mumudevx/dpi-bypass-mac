package netwatch

import (
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/netstate"
)

func facts(v netstate.VPNState) *netstate.Facts {
	return &netstate.Facts{Uplink: "en0", VPN: v}
}

func TestClassifyVPN(t *testing.T) {
	cases := []struct {
		name           string
		facts          *netstate.Facts
		requireCapture bool
		wantFatal      bool
		wantPresent    bool
		wantDetail     string
	}{
		{
			name:  "no facts at all is not a VPN",
			facts: nil,
		},
		{
			name:  "no VPN",
			facts: facts(netstate.VPNState{}),
		},
		{
			// The wave 1 review's second defect: a rollback deleted a
			// coexisting VPN's half-default. A split tunnel must never be
			// fatal and must never be described as something to act on.
			name:           "a split tunnel is never fatal, in either mode",
			facts:          facts(netstate.VPNState{Present: true, Iface: "utun4", ServiceName: "Work VPN"}),
			requireCapture: true,
			wantPresent:    true,
			wantDetail:     "left alone",
		},
		{
			name: "a full tunnel under the proxy front end is reported and lived with",
			facts: facts(netstate.VPNState{
				Present: true, FullTunnel: true, Iface: "utun6", ServiceName: "Mullvad",
			}),
			requireCapture: false,
			wantPresent:    true,
			wantDetail:     "the proxy still works",
		},
		{
			name: "a full tunnel under a run that must capture is the exit-5 refusal",
			facts: facts(netstate.VPNState{
				Present: true, FullTunnel: true, Iface: "utun6", ServiceName: "Mullvad",
			}),
			requireCapture: true,
			wantFatal:      true,
			wantPresent:    true,
			wantDetail:     "stopping rather than reporting success",
		},
		{
			name: "an unnamed full tunnel still names its interface",
			facts: facts(netstate.VPNState{
				Present: true, FullTunnel: true, Iface: "utun6",
			}),
			requireCapture: true,
			wantFatal:      true,
			wantPresent:    true,
			wantDetail:     "utun6",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := ClassifyVPN(tc.facts, tc.requireCapture)
			if v.Fatal != tc.wantFatal {
				t.Errorf("Fatal = %v, want %v", v.Fatal, tc.wantFatal)
			}
			if v.Present != tc.wantPresent {
				t.Errorf("Present = %v, want %v", v.Present, tc.wantPresent)
			}
			if tc.wantFatal {
				if !errors.Is(v.Err, ErrFullTunnelVPN) {
					t.Errorf("Err = %v, want it to wrap ErrFullTunnelVPN", v.Err)
				}
			} else if v.Err != nil {
				t.Errorf("Err = %v, want nil for a non-fatal verdict", v.Err)
			}
			if tc.wantDetail != "" && !strings.Contains(v.Detail, tc.wantDetail) {
				t.Errorf("Detail = %q, want it to mention %q", v.Detail, tc.wantDetail)
			}
		})
	}
}

// TestClassifyVPNCarriesTheInterfaceName pins that the refusal message names
// the tunnel, because "a VPN is in the way" without saying which one leaves a
// user with nothing to switch off.
func TestClassifyVPNCarriesTheInterfaceName(t *testing.T) {
	v := ClassifyVPN(facts(netstate.VPNState{
		Present: true, FullTunnel: true, Iface: "utun9", ServiceName: "Corp",
	}), true)
	if v.Iface != "utun9" {
		t.Fatalf("Iface = %q, want utun9", v.Iface)
	}
	if !strings.Contains(v.Err.Error(), "utun9") {
		t.Fatalf("the error does not name the interface: %v", v.Err)
	}
	if !strings.Contains(v.Detail, "Corp") {
		t.Fatalf("the detail does not name the service: %q", v.Detail)
	}
}

func TestNameOr(t *testing.T) {
	if got := nameOr("a", "b"); got != "a" {
		t.Errorf("nameOr(a,b) = %q", got)
	}
	if got := nameOr("", "b"); got != "b" {
		t.Errorf("nameOr(,b) = %q", got)
	}
	if got := nameOr("", ""); got != "unnamed" {
		t.Errorf("nameOr(,) = %q", got)
	}
}
