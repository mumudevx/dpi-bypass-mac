package flow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// Target is one upstream destination.
//
// Name is the hostname the client asked for, which is the only thing the policy
// layer and the strategy layer ever key on. Addr is a pinned address: when it is
// set, no name resolution happens at all, which is what makes `dpb probe
// --addr` measure the origin rather than whatever the system resolver returned.
type Target struct {
	Name string
	Addr netip.AddrPort
	Port int
}

// String renders the target the way a log line and `dpb why` want it.
func (t Target) String() string {
	switch {
	case t.Name != "" && t.Addr.IsValid():
		return fmt.Sprintf("%s[%s]", net.JoinHostPort(t.Name, strconv.Itoa(t.dstPort())), t.Addr)
	case t.Name != "":
		return net.JoinHostPort(t.Name, strconv.Itoa(t.dstPort()))
	case t.Addr.IsValid():
		return t.Addr.String()
	}
	return "<empty target>"
}

// dstPort is the destination port: the explicit Port when set, otherwise the
// port carried by a pinned Addr.
func (t Target) dstPort() int {
	if t.Port != 0 {
		return t.Port
	}
	return int(t.Addr.Port())
}

// pinned reports the address to dial when the caller already resolved one.
func (t Target) pinned() (netip.AddrPort, bool) {
	if !t.Addr.Addr().IsValid() {
		return netip.AddrPort{}, false
	}
	port := t.Addr.Port()
	if port == 0 {
		port = uint16(t.dstPort())
	}
	if port == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(t.Addr.Addr().Unmap(), port), true
}

// Dialer opens the upstream connection an attempt is emitted on. Every rung of
// the ladder gets a FRESH connection from it: a censored handshake leaves the
// socket in a state no strategy can rescue.
type Dialer interface {
	DialTCP(ctx context.Context, t Target) (net.Conn, error)
}

// ResolveFunc turns a name into addresses. Its signature is resolve.Chain.Resolve
// exactly, and it is a function type rather than an import so that flow does not
// depend on the resolver package — but it is also the ONLY way a name becomes an
// address in this package.
//
// MEASUREMENTS.md §5.4: the first run of the compatibility matrix scored every
// emitter 0/6 because Go's resolver returned the BTK sinkhole 195.175.254.2 and
// every connection reached the block page instead of the origin. A dialer with
// no ResolveFunc therefore refuses a name outright rather than falling back to
// the system resolver.
type ResolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// ErrNoResolver is returned when a Target carries a name, no pinned address, and
// the dialer has no chain to resolve through.
var ErrNoResolver = errors.New("flow: no resolver chain: a name may only be resolved through resolve.Chain (MEASUREMENTS.md 5.4)")

// DefaultDialTimeout bounds a single address attempt. The ladder's own budget
// bounds the walk; this bounds one rung so a blackholed address cannot spend it
// all.
const DefaultDialTimeout = 5 * time.Second

// NetDialer is the shipped Dialer: an ordinary kernel socket, optionally pinned
// to the uplink interface, with TCP_NODELAY set before the first byte.
//
// Both front-ends use it, so both emit through the same emit.SockTransport with
// the same capabilities, and TUN mode adds coverage rather than techniques.
type NetDialer struct {
	// Resolve is the tool's own chain. Nil means only pinned addresses may be
	// dialled.
	Resolve ResolveFunc
	// Interface pins the socket to an uplink by name (IP_BOUND_IF). It is what
	// stops our own upstream connections from being captured by the default
	// route we install over the tunnel in TUN mode. Empty leaves the socket on
	// the system's routing decision, which is correct for proxy mode.
	Interface string
	// Timeout bounds one address attempt. Zero means DefaultDialTimeout.
	Timeout time.Duration
	// KeepAlive is passed to net.Dialer. Zero leaves Go's default.
	KeepAlive time.Duration
	Logf      func(string, ...any)
}

var _ Dialer = (*NetDialer)(nil)

func (d *NetDialer) logf(format string, a ...any) {
	if d.Logf != nil {
		d.Logf(format, a...)
	}
}

// DialTCP connects to t, trying each candidate address in order.
func (d *NetDialer) DialTCP(ctx context.Context, t Target) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	addrs, err := d.candidates(ctx, t)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("flow: dial %s: no usable address", t)
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}

	var lastErr error
	for _, ap := range addrs {
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("flow: dial %s: %w", t, cerr)
		}
		nd := net.Dialer{
			Timeout:   timeout,
			KeepAlive: d.KeepAlive,
			Control:   d.control,
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		c, derr := nd.DialContext(attemptCtx, networkFor(ap.Addr()), ap.String())
		cancel()
		if derr == nil {
			return c, nil
		}
		lastErr = derr
		d.logf("flow: dial %s via %s failed: %v", t, ap, derr)
	}
	return nil, fmt.Errorf("flow: dial %s: %w", t, lastErr)
}

// candidates is the address list to try, in order.
func (d *NetDialer) candidates(ctx context.Context, t Target) ([]netip.AddrPort, error) {
	if ap, ok := t.pinned(); ok {
		return []netip.AddrPort{ap}, nil
	}
	if t.Name == "" {
		return nil, fmt.Errorf("flow: dial: target has neither a name nor an address")
	}
	port := t.dstPort()
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("flow: dial %q: port %d is out of range", t.Name, port)
	}
	if d.Resolve == nil {
		return nil, fmt.Errorf("flow: dial %q: %w", t.Name, ErrNoResolver)
	}
	ips, err := d.Resolve(ctx, t.Name)
	if err != nil {
		return nil, fmt.Errorf("flow: resolve %q: %w", t.Name, err)
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("flow: resolve %q: chain returned no usable address", t.Name)
	}
	return out, nil
}

// control runs on the raw socket before connect. Both settings must happen here
// rather than after the dial: TCP_NODELAY has to be in force for the very first
// write (a two-record ClientHello must leave as ONE segment, MEASUREMENTS.md
// §3.1), and an interface binding after connect is too late to matter.
func (d *NetDialer) control(network, address string, c syscall.RawConn) error {
	var errs []error
	if cerr := c.Control(func(fd uintptr) {
		if err := setNoDelay(fd); err != nil {
			errs = append(errs, fmt.Errorf("set TCP_NODELAY: %w", err))
		}
		if d.Interface != "" {
			if err := bindToInterface(fd, d.Interface, isV6Network(network, address)); err != nil {
				errs = append(errs, fmt.Errorf("bind to %s: %w", d.Interface, err))
			}
		}
	}); cerr != nil {
		return fmt.Errorf("flow: dial control: %w", cerr)
	}
	return errors.Join(errs...)
}

func setNoDelay(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
}

func networkFor(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "tcp4"
	}
	return "tcp6"
}

func isV6Network(network, address string) bool {
	switch network {
	case "tcp4", "udp4", "ip4":
		return false
	case "tcp6", "udp6", "ip6":
		return true
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Is6() && !a.Is4In6()
		}
	}
	return false
}
