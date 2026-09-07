package flow_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
)

func TestNetDialerPinnedAddress(t *testing.T) {
	t.Parallel()
	addr := rawOrigin(t, []byte("hello"))
	ap := netip.MustParseAddrPort(addr)

	d := &flow.NetDialer{Timeout: 2 * time.Second}
	c, err := d.DialTCP(context.Background(), flow.Target{Name: "discord.com", Addr: ap, Port: 443})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*net.TCPConn); !ok {
		t.Fatalf("dialled a %T; the ladder needs a *net.TCPConn to build a SockTransport", c)
	}
}

// TestNetDialerRefusesToResolve is MEASUREMENTS.md §5.4 as a unit test. A name
// with no chain must fail loudly, never fall through to Go's resolver — which on
// the measured line answers the BTK sinkhole for every blocked name.
func TestNetDialerRefusesToResolve(t *testing.T) {
	t.Parallel()
	d := &flow.NetDialer{}
	_, err := d.DialTCP(context.Background(), flow.Target{Name: "discord.com", Port: 443})
	if !errors.Is(err, flow.ErrNoResolver) {
		t.Fatalf("err = %v, want ErrNoResolver", err)
	}
}

func TestNetDialerUsesTheSuppliedChain(t *testing.T) {
	t.Parallel()
	addr := rawOrigin(t, []byte("hello"))
	ap := netip.MustParseAddrPort(addr)

	var asked string
	d := &flow.NetDialer{
		Timeout: 2 * time.Second,
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			asked = host
			return []netip.Addr{ap.Addr()}, nil
		},
	}
	c, err := d.DialTCP(context.Background(), flow.Target{Name: "discord.com", Port: int(ap.Port())})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer c.Close()
	if asked != "discord.com" {
		t.Fatalf("chain was asked for %q, want discord.com", asked)
	}
}

func TestNetDialerTriesEveryAddress(t *testing.T) {
	t.Parallel()
	addr := rawOrigin(t, []byte("hello"))
	ap := netip.MustParseAddrPort(addr)

	// 127.0.0.2 is loopback but nothing listens there, so it refuses at once —
	// the shape a chain that returned a stale address produces.
	d := &flow.NetDialer{
		Timeout: 2 * time.Second,
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.2"), ap.Addr()}, nil
		},
		Logf: func(string, ...any) {},
	}
	c, err := d.DialTCP(context.Background(), flow.Target{Name: "x.example", Port: int(ap.Port())})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer c.Close()
	if got := c.RemoteAddr().String(); got != addr {
		t.Fatalf("connected to %s, want the second candidate %s", got, addr)
	}
}

func TestNetDialerReportsTheLastError(t *testing.T) {
	t.Parallel()
	d := &flow.NetDialer{
		Timeout: 2 * time.Second,
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
		},
	}
	// Port 1 on loopback: nothing listens, so this refuses rather than hanging.
	if _, err := d.DialTCP(context.Background(), flow.Target{Name: "x.example", Port: 1}); err == nil {
		t.Fatal("want an error when no candidate answers")
	}
}

func TestNetDialerRejectsAnEmptyTarget(t *testing.T) {
	t.Parallel()
	d := &flow.NetDialer{}
	if _, err := d.DialTCP(context.Background(), flow.Target{}); err == nil {
		t.Fatal("want an error for a target with neither a name nor an address")
	}
	if _, err := d.DialTCP(context.Background(), flow.Target{Name: "x", Port: 70000}); err == nil {
		t.Fatal("want an error for an out-of-range port")
	}
}

func TestNetDialerResolveFailure(t *testing.T) {
	t.Parallel()
	d := &flow.NetDialer{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("chain exhausted")
	}}
	if _, err := d.DialTCP(context.Background(), flow.Target{Name: "x.example", Port: 443}); err == nil ||
		!strings.Contains(err.Error(), "chain exhausted") {
		t.Fatalf("err = %v, want the chain's error surfaced", err)
	}

	d2 := &flow.NetDialer{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{{}}, nil
	}}
	if _, err := d2.DialTCP(context.Background(), flow.Target{Name: "x.example", Port: 443}); err == nil {
		t.Fatal("want an error when the chain returns no usable address")
	}
}

// TestNetDialerBindsToAnInterface: an unknown uplink name is an error, not a
// silent unbound socket. In TUN mode an unbound socket is routed back into our
// own tunnel and loops.
func TestNetDialerBindsToAnInterface(t *testing.T) {
	t.Parallel()
	addr := rawOrigin(t, []byte("hello"))
	ap := netip.MustParseAddrPort(addr)
	d := &flow.NetDialer{Timeout: time.Second, Interface: "nosuchif0"}
	if _, err := d.DialTCP(context.Background(), flow.Target{Addr: ap, Port: 443}); err == nil {
		t.Fatal("want an error when the uplink cannot be bound")
	}
}

func TestNetDialerCancelledContext(t *testing.T) {
	t.Parallel()
	addr := rawOrigin(t, []byte("hello"))
	ap := netip.MustParseAddrPort(addr)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &flow.NetDialer{}
	if _, err := d.DialTCP(ctx, flow.Target{Addr: ap, Port: 443}); err == nil {
		t.Fatal("want an error under a cancelled context")
	}
}

func TestTargetString(t *testing.T) {
	t.Parallel()
	ap := netip.MustParseAddrPort("192.0.2.10:443")
	cases := []struct {
		t    flow.Target
		want string
	}{
		{flow.Target{Name: "discord.com", Addr: ap, Port: 443}, "discord.com:443[192.0.2.10:443]"},
		{flow.Target{Name: "discord.com", Port: 443}, "discord.com:443"},
		{flow.Target{Addr: ap}, "192.0.2.10:443"},
		{flow.Target{}, "<empty target>"},
	}
	for _, c := range cases {
		if got := c.t.String(); got != c.want {
			t.Errorf("Target.String() = %q, want %q", got, c.want)
		}
	}
}

// TestTargetPortFallback: a pinned AddrPort with no explicit Port still dials
// the right port, and an explicit Port still names the flow for policy.
func TestTargetPortFallback(t *testing.T) {
	t.Parallel()
	addr := rawOrigin(t, []byte("hello"))
	ap := netip.MustParseAddrPort(addr)
	d := &flow.NetDialer{Timeout: time.Second}
	c, err := d.DialTCP(context.Background(), flow.Target{Addr: ap})
	if err != nil {
		t.Fatalf("DialTCP with only a pinned AddrPort: %v", err)
	}
	defer c.Close()
	if got := c.RemoteAddr().String(); got != addr {
		t.Fatalf("connected to %s, want %s", got, addr)
	}
}
