//go:build darwin

package flow

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bindToInterface pins a socket to one interface with IP_BOUND_IF, so the
// routing table cannot move it.
//
// This is what keeps dpb's own upstream connections off the tunnel in TUN mode.
// The capture routes we install (0.0.0.0/1 and 128.0.0.0/1 via utunN) cover the
// whole address space, so an unbound upstream socket would be routed straight
// back into our own netstack and loop. The interface-scoped default route the
// bring-up adds is the other half of the pair: IP_BOUND_IF selects the scope,
// the scoped route supplies the gateway.
func bindToInterface(fd uintptr, name string, v6 bool) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("look up interface %q: %w", name, err)
	}
	level, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if v6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	if err := unix.SetsockoptInt(int(fd), level, opt, ifi.Index); err != nil {
		return fmt.Errorf("IP_BOUND_IF %s (index %d): %w", name, ifi.Index, err)
	}
	return nil
}
