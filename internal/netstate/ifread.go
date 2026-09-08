package netstate

import (
	"fmt"
	"net"
	"net/netip"
)

// This is the kernel read-back half of ifconfigOp's verification, and it stays
// in netstate on purpose while the mutation itself moved behind the Port.
//
// Two reasons, and the second is the load-bearing one:
//
//  1. net.Interfaces() is portable Go. It reads identically on Windows with
//     different syscalls underneath, which is exactly the dividing line this
//     phase applies — nothing here names a macOS tool or flag.
//  2. sysport.IfaceController.Addrs answers "which addresses does this
//     interface carry", and Verify asks three questions: does the device exist,
//     is it up, does it have the MTU we set, and only then does it carry our
//     address. An MTU that did not take is a real failure this Op has seen
//     (ifconfig reports success and the interface keeps its old MTU), so
//     dropping to the addresses alone would delete a check rather than move it.
//
// scdarwin has its own copy of the same seams for Addrs. That duplication is
// deliberate: the two are read through different code paths on purpose, and a
// divergence between them would be a real disagreement about what the kernel
// says, not an accident of transcription.

// interfaceLister is a seam so Verify paths that read net.Interfaces() can be
// driven by a fake system in tests. It is deliberately not part of Env: every
// production caller wants the real kernel.
var interfaceLister = net.Interfaces

// interfaceAddrser mirrors interfaceLister for per-interface addresses.
var interfaceAddrser = func(in *net.Interface) ([]net.Addr, error) { return in.Addrs() }

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
