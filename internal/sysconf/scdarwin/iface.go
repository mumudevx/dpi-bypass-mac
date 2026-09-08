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

// SetAddr assigns local (and peer, for IPv4 point-to-point) to iface.
func (c ifaceCtl) SetAddr(ctx context.Context, iface, local, peer string) error {
	args := []string{iface, addrFamily(local), local}
	switch {
	case isV6Addr(local):
		args = append(args, "prefixlen", "64")
	case peer != "":
		// A utun is point-to-point: without a peer the kernel has no destination
		// to attach the interface route to.
		args = append(args, peer)
	}
	return c.p.run.Run(ctx, "ifconfig", args...).Error()
}

func (c ifaceCtl) SetMTU(ctx context.Context, iface string, mtu int) error {
	return c.p.run.Run(ctx, "ifconfig", iface, "mtu", strconv.Itoa(mtu)).Error()
}

func (c ifaceCtl) Up(ctx context.Context, iface string) error {
	return c.p.run.Run(ctx, "ifconfig", iface, "up").Error()
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

// AddrRemover removes an address from an interface. sysport.IfaceController has
// no such method — every mutation it declares has a counterpart on Windows and
// this one does not yet — so the revert path reaches it by asserting for this
// interface rather than by widening the contract before there is a second
// implementation to widen it for.
type AddrRemover interface {
	RemoveAddr(ctx context.Context, iface, local string) error
}

// RemoveAddr removes an address from an interface. Bringing the interface down
// is deliberately not attempted: the utun belongs to whoever opened its file
// descriptor, and it disappears when they close it.
//
// An already-gone utun makes ifconfig say "does not exist". That is the success
// case for a revert, so the error is reported and the caller's kernel read is
// what decides.
func (c ifaceCtl) RemoveAddr(ctx context.Context, iface, local string) error {
	return c.p.run.Run(ctx, "ifconfig", iface, addrFamily(local), local, "-alias").Error()
}

var _ AddrRemover = ifaceCtl{}

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
