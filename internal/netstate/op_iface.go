package netstate

import (
	"context"
	"fmt"
	"net"

	"github.com/mumudevx/dpb/internal/sysport"
)

func init() { reviveByKind[OpIfconfig] = reviveIfconfig }

type ifconfigRevert struct {
	Iface string `json:"iface"`
	Local string `json:"local"`
	Peer  string `json:"peer,omitempty"`
	MTU   int    `json:"mtu,omitempty"`
}

// ifconfigOp configures a utun's addresses and MTU through the Port and
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

// sys is the Port this Op mutates through, built from the Op's own Runner when
// it has one. See routeOp.sys.
func (o *ifconfigOp) sys(e Env) Port {
	env := e
	env.Runner = o.runner(e)
	return env.sys()
}

// cfg is the state the device should be in. There is no family field: the
// family follows from the address, and a flag beside it could disagree.
func (o *ifconfigOp) cfg() sysport.IfaceConfig {
	return sysport.IfaceConfig{Local: o.local, Peer: o.peer, MTU: o.mtu}
}

func (o *ifconfigOp) Apply(ctx context.Context, e Env) error {
	return o.sys(e).Iface().Configure(ctx, o.iface, o.cfg())
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
	if err := o.sys(e).Iface().Unconfigure(ctx, o.iface, o.cfg()); err != nil {
		// An already-gone utun makes ifconfig say "does not exist". That is the
		// success case for a revert, so the kernel read below decides, not this.
		e.logf("netstate: ifconfig -alias reported %q; the interface read decides", err)
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
