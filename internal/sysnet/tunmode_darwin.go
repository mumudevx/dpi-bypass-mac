//go:build darwin

package sysnet

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DialFunc dials a destination, used by the TUN front-end for upstream sockets.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DefaultInterface returns the physical interface carrying the default route
// (e.g. en0), used both for IP_BOUND_IF and as the uplink.
func DefaultInterface(ctx context.Context, runner CommandRunner) string {
	if runner == nil {
		runner = ExecRunner{}
	}
	out, err := runner.Run(ctx, "route", "-n", "get", "default")
	if err != nil {
		return ""
	}
	m := defaultIfaceRe.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1]
}

// BoundDialer returns a DialFunc whose sockets are bound to the given physical
// interface via IP_BOUND_IF / IPV6_BOUND_IF. This is what prevents the upstream
// connection from being routed back into the utun (a packet loop).
func BoundDialer(iface string, timeout time.Duration) (DialFunc, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("bound dialer: %w", err)
	}
	idx := ifi.Index
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(network, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				if strings.HasSuffix(network, "6") {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
				} else {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
				}
			}); err != nil {
				return err
			}
			return serr
		},
	}
	return d.DialContext, nil
}

// RouteManager brings up the utun interface and adds/removes routes, journaling
// every change for guaranteed teardown. Because interface-scoped routes vanish
// when the utun device is closed, a kill -9 self-heals (the routes disappear
// with the interface); the journal handles the graceful-exit case.
type RouteManager struct {
	runner  CommandRunner
	iface   string
	journal [][]string // route-delete argv to replay on teardown
	logf    func(string, ...any)
}

// NewRouteManager builds a RouteManager for the given utun interface.
func NewRouteManager(iface string, runner CommandRunner, logf func(string, ...any)) *RouteManager {
	if runner == nil {
		runner = ExecRunner{}
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &RouteManager{iface: iface, runner: runner, logf: logf}
}

// Configure assigns the point-to-point addresses and MTU and brings the
// interface up.
func (r *RouteManager) Configure(ctx context.Context, localAddr, peerAddr string, mtu int) error {
	_, err := r.runner.Run(ctx, "ifconfig", r.iface, localAddr, peerAddr, "mtu", fmt.Sprintf("%d", mtu), "up")
	if err != nil {
		return fmt.Errorf("ifconfig %s: %w", r.iface, err)
	}
	return nil
}

// AddRoute routes a destination CIDR through the utun interface.
func (r *RouteManager) AddRoute(ctx context.Context, cidr string) error {
	if _, err := r.runner.Run(ctx, "route", "-q", "add", "-net", cidr, "-interface", r.iface); err != nil {
		return fmt.Errorf("route add %s: %w", cidr, err)
	}
	r.journal = append(r.journal, []string{"-q", "delete", "-net", cidr, "-interface", r.iface})
	return nil
}

// CaptureAll installs a split-default (0.0.0.0/1 + 128.0.0.0/1) so all IPv4
// traffic is pulled into the utun without removing the original default route.
func (r *RouteManager) CaptureAll(ctx context.Context) error {
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := r.AddRoute(ctx, cidr); err != nil {
			return err
		}
	}
	return nil
}

// Teardown removes every route added by this manager. Idempotent.
func (r *RouteManager) Teardown(ctx context.Context) {
	for i := len(r.journal) - 1; i >= 0; i-- {
		if _, err := r.runner.Run(ctx, "route", r.journal[i]...); err != nil {
			r.logf("sysnet: route %v: %v", r.journal[i], err)
		}
	}
	r.journal = nil
}
