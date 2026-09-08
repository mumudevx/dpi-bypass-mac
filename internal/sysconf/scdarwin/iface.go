//go:build darwin

package scdarwin

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/mumudevx/dpb/internal/sysport"
)

// ifaceCtl configures a utun's addresses and MTU with ifconfig(8) and reads the
// result back through net.Interfaces(), which asks the kernel directly rather
// than asking the tool that just claimed to have configured it.
type ifaceCtl struct{ p *port }

var _ sysport.IfaceController = ifaceCtl{}

// Configure emits one ifconfig invocation carrying the address, the peer or
// prefix length, the MTU and "up". It is one call because that is what macOS
// takes: issuing the same settings as three commands would show the kernel a
// different argv, and an interface that is up with an address but no MTU
// between two of them.
func (c ifaceCtl) Configure(ctx context.Context, iface string, cfg sysport.IfaceConfig) error {
	return c.p.run.Run(ctx, "ifconfig", configureArgs(iface, cfg)...).Error()
}

func configureArgs(iface string, cfg sysport.IfaceConfig) []string {
	args := []string{iface, addrFamily(cfg.Local), cfg.Local}
	switch {
	case isV6Addr(cfg.Local):
		args = append(args, "prefixlen", "64")
	case cfg.Peer != "":
		// A utun is point-to-point: without a peer the kernel has no destination
		// to attach the interface route to.
		args = append(args, cfg.Peer)
	}
	if cfg.MTU > 0 {
		args = append(args, "mtu", strconv.Itoa(cfg.MTU))
	}
	return append(args, "up")
}

// Unconfigure removes the address. Bringing the interface down is deliberately
// not attempted: the utun belongs to whoever opened its file descriptor, and it
// disappears when they close it.
//
// An already-gone utun makes ifconfig say "does not exist". That is the success
// case for a revert, so the error is reported and the caller's kernel read is
// what decides.
func (c ifaceCtl) Unconfigure(ctx context.Context, iface string, cfg sysport.IfaceConfig) error {
	return c.p.run.Run(ctx, "ifconfig", iface, addrFamily(cfg.Local), cfg.Local, "-alias").Error()
}

// Addrs reads an interface's addresses out of the kernel. An interface that
// does not exist carries no addresses, which is the right answer for a utun
// that has already gone away with the file descriptor that owned it.
func (c ifaceCtl) Addrs(_ context.Context, iface string) ([]netip.Addr, error) {
	in, ok, err := findInterface(iface)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	addrs, err := interfaceAddrser(in)
	if err != nil {
		return nil, fmt.Errorf("netstate: read addresses of %s: %w", in.Name, err)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		got, ok := addrOfNetAddr(a)
		if !ok {
			continue
		}
		out = append(out, got)
	}
	return out, nil
}

func isV6Addr(local string) bool { return strings.Contains(local, ":") }

func addrFamily(local string) string {
	if isV6Addr(local) {
		return "inet6"
	}
	return "inet"
}

func findInterface(name string) (*net.Interface, bool, error) {
	ifs, err := interfaceLister()
	if err != nil {
		return nil, false, fmt.Errorf("netstate: enumerate interfaces: %w", err)
	}
	for i := range ifs {
		if ifs[i].Name == name {
			return &ifs[i], true, nil
		}
	}
	return nil, false, nil
}

func addrOfNetAddr(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.IPNet:
		return netip.AddrFromSlice(v.IP)
	case *net.IPAddr:
		return netip.AddrFromSlice(v.IP)
	default:
		addr, err := netip.ParsePrefix(a.String())
		if err == nil {
			return addr.Addr(), true
		}
		got, err := netip.ParseAddr(a.String())
		return got, err == nil
	}
}
