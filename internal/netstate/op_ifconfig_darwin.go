package netstate

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func init() { reviveByKind[OpIfconfig] = reviveIfconfig }

type ifconfigRevert struct {
	Iface string `json:"iface"`
	Local string `json:"local"`
	Peer  string `json:"peer,omitempty"`
	MTU   int    `json:"mtu,omitempty"`
}

// ifconfigOp configures a utun's addresses and MTU with ifconfig(8) and
// verifies the result through net.Interfaces(), which asks the kernel directly
// rather than asking the tool that just claimed to have configured it.
type ifconfigOp struct {
	run   Runner
	iface string
	local string
	peer  string
	mtu   int
}

// NewIfconfig returns an Op assigning local (and peer, for IPv4
// point-to-point) to iface, setting its MTU and bringing it up.
func NewIfconfig(r Runner, iface, local, peer string, mtu int) Op {
	return &ifconfigOp{run: r, iface: iface, local: local, peer: peer, mtu: mtu}
}

func (o *ifconfigOp) Kind() OpKind { return OpIfconfig }
func (o *ifconfigOp) ID() string   { return fmt.Sprintf("ifconfig:%s/%s", o.iface, o.local) }

func (o *ifconfigOp) Describe() string {
	if o.peer != "" {
		return fmt.Sprintf("configure %s %s -> %s mtu %d up", o.iface, o.local, o.peer, o.mtu)
	}
	return fmt.Sprintf("configure %s %s mtu %d up", o.iface, o.local, o.mtu)
}

func (o *ifconfigOp) runner(e Env) Runner {
	if o.run != nil {
		return o.run
	}
	return e.runner()
}

func (o *ifconfigOp) isV6() bool { return strings.Contains(o.local, ":") }

func (o *ifconfigOp) family() string {
	if o.isV6() {
		return "inet6"
	}
	return "inet"
}

func (o *ifconfigOp) applyArgs() []string {
	args := []string{o.iface, o.family(), o.local}
	switch {
	case o.isV6():
		args = append(args, "prefixlen", "64")
	case o.peer != "":
		// A utun is point-to-point: without a peer the kernel has no destination
		// to attach the interface route to.
		args = append(args, o.peer)
	}
	if o.mtu > 0 {
		args = append(args, "mtu", strconv.Itoa(o.mtu))
	}
	return append(args, "up")
}

func (o *ifconfigOp) Apply(ctx context.Context, e Env) error {
	return o.runner(e).Run(ctx, "ifconfig", o.applyArgs()...).Error()
}

func (o *ifconfigOp) Verify(_ context.Context, _ Env) error {
	in, ok, err := findInterface(o.iface)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("interface %s does not exist", o.iface)
	}
	if in.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is not up", o.iface)
	}
	if o.mtu > 0 && in.MTU != o.mtu {
		return fmt.Errorf("interface %s has MTU %d, want %d", o.iface, in.MTU, o.mtu)
	}
	has, err := interfaceHasAddr(in, o.local)
	if err != nil {
		return err
	}
	if !has {
		return fmt.Errorf("interface %s does not carry address %s", o.iface, o.local)
	}
	return nil
}

// Revert removes the address. Bringing the interface down is deliberately not
// attempted: the utun belongs to whoever opened its file descriptor, and it
// disappears when they close it.
func (o *ifconfigOp) Revert(ctx context.Context, e Env) error {
	if res := o.runner(e).Run(ctx, "ifconfig", o.iface, o.family(), o.local, "-alias"); res.Failed() {
		// An already-gone utun makes ifconfig say "does not exist". That is the
		// success case for a revert, so the kernel read below decides, not this.
		e.logf("netstate: ifconfig -alias reported %q; the interface read decides", res.Reason())
	}
	return nil
}

func (o *ifconfigOp) VerifyReverted(_ context.Context, _ Env) error {
	in, ok, err := findInterface(o.iface)
	if err != nil {
		return err
	}
	if !ok {
		return nil // the whole device is gone, which is the strongest revert there is
	}
	has, err := interfaceHasAddr(in, o.local)
	if err != nil {
		return err
	}
	if has {
		return fmt.Errorf("interface %s still carries address %s", o.iface, o.local)
	}
	return nil
}

func (o *ifconfigOp) Record() Record {
	raw, err := marshalRevert(ifconfigRevert{Iface: o.iface, Local: o.local, Peer: o.peer, MTU: o.mtu})
	rec := Record{Kind: OpIfconfig, ID: o.ID(), Revert: raw}
	if err != nil {
		rec.Note = err.Error()
	}
	return rec
}

func reviveIfconfig(r Record) (Op, error) {
	var p ifconfigRevert
	if err := unmarshalRevert(r.Revert, &p); err != nil {
		return nil, err
	}
	if p.Iface == "" || p.Local == "" {
		return nil, fmt.Errorf("netstate: ifconfig record is missing the interface or address")
	}
	return &ifconfigOp{iface: p.Iface, local: p.Local, peer: p.Peer, mtu: p.MTU}, nil
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

func interfaceHasAddr(in *net.Interface, want string) (bool, error) {
	wantAddr, err := netip.ParseAddr(want)
	if err != nil {
		return false, fmt.Errorf("netstate: %q is not an IP address: %w", want, err)
	}
	addrs, err := interfaceAddrser(in)
	if err != nil {
		return false, fmt.Errorf("netstate: read addresses of %s: %w", in.Name, err)
	}
	for _, a := range addrs {
		got, ok := addrOfNetAddr(a)
		if !ok {
			continue
		}
		if got.WithZone("").Unmap() == wantAddr.WithZone("").Unmap() {
			return true, nil
		}
	}
	return false, nil
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
