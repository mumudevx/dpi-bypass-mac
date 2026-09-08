package netstate

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/mumudevx/dpb/internal/sysport"
	"github.com/mumudevx/dpb/internal/testport"
)

// errAddFailed is the scripted failure a real `route add` reports as the
// exit-0 "File exists" liar: the destination was already owned by somebody
// else, and route(8) itself never distinguishes that from genuine success.
var errAddFailed = errors.New("route add: File exists")

// A failed Add must leave nothing to roll back. The exit-0 "File exists" liar
// is the common shape: the destination was already owned by somebody else, and
// issuing the delete anyway would remove their route rather than ours.
func TestRouteOpDoesNotRollBackAFailedAdd(t *testing.T) {
	p := testport.New()
	p.RouteC.AddErr = errAddFailed
	op := NewRoute(nil, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun9").(*routeOp)

	if err := op.Apply(context.Background(), Env{Sys: p}); err == nil {
		t.Fatal("Apply() = nil, want the Add error")
	}
	if op.mutated() {
		t.Error("mutated() = true after a failed Add; rollback would delete another owner's route")
	}
	if n := len(p.RouteC.Deletes); n != 0 {
		t.Errorf("Deletes = %d, want 0", n)
	}
}

// TestRouteOpSpecShapes asserts the RouteSpec routeOp.Apply hands the Port for
// each of the three shapes sysport.RouteSpec documents. This is the thing a
// tool-output fake cannot check at all: fakesystem_test.go can confirm the
// argv route(8) received, but only a Port-level fake can confirm the
// platform-independent value an Op decided on before any argv existed —
// which is what the Windows implementation will be handed instead.
func TestRouteOpSpecShapes(t *testing.T) {
	cases := []struct {
		name  string
		dst   string
		gw    string // "" means no gateway (an interface route)
		iface string
		want  sysport.RouteSpec
	}{
		{
			name:  "scoped gateway",
			dst:   "0.0.0.0/0",
			gw:    "192.168.0.1",
			iface: "en0",
			want: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("0.0.0.0/0"),
				Gw:    netip.MustParseAddr("192.168.0.1"),
				Iface: "en0",
			},
		},
		{
			name: "plain gateway",
			dst:  "10.0.0.0/8",
			gw:   "192.168.0.1",
			want: sysport.RouteSpec{
				Dst: netip.MustParsePrefix("10.0.0.0/8"),
				Gw:  netip.MustParseAddr("192.168.0.1"),
			},
		},
		{
			name:  "interface route",
			dst:   "0.0.0.0/1",
			iface: "utun9",
			want: sysport.RouteSpec{
				Dst:   netip.MustParsePrefix("0.0.0.0/1"),
				Iface: "utun9",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gw netip.Addr
			if tc.gw != "" {
				gw = netip.MustParseAddr(tc.gw)
			}
			p := testport.New()
			op := NewRoute(nil, netip.MustParsePrefix(tc.dst), gw, tc.iface)

			if err := op.Apply(context.Background(), Env{Sys: p}); err != nil {
				t.Fatalf("Apply() = %v", err)
			}
			if len(p.RouteC.Adds) != 1 {
				t.Fatalf("Adds = %d, want 1", len(p.RouteC.Adds))
			}
			if got := p.RouteC.Adds[0]; got != tc.want {
				t.Errorf("RouteSpec = %+v, want %+v", got, tc.want)
			}
		})
	}
}
