//go:build windows

package flow

import (
	"fmt"
	"net"
	"syscall"
)

// setNoDelay disables Nagle; see the comment in dialer_unix.go for why every
// rung depends on it. Winsock's setsockopt takes a Handle rather than an int,
// which is the whole reason this file exists.
func setNoDelay(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
}

// IP_UNICAST_IF and IPV6_UNICAST_IF are not among the option constants the
// standard syscall package defines for windows -- only IPPROTO_IP and
// IPPROTO_IPV6 are (see $GOROOT/src/syscall/types_windows.go). Both numbers
// come from Winsock's ws2ipdef.h and are confirmed against this module's own
// vendored golang.zx2c4.com/wireguard/conn/bind_windows.go, which defines and
// uses the identical constants (as IP_UNICAST_IF / IPV6_UNICAST_IF, both 31)
// to pin wireguard's own UDP sockets on Windows.
const (
	ipUnicastIF   = 31 // IPPROTO_IP level
	ipv6UnicastIF = 31 // IPPROTO_IPV6 level -- same number, different level, no collision
)

// bindToInterface pins a socket to one interface with IP_UNICAST_IF (v4) or
// IPV6_UNICAST_IF (v6), so Windows' route lookup for that socket can only see
// the uplink's own default route -- never the capture routes TUN mode
// installs. See dialer_darwin.go's bindToInterface for the shared rationale
// (the 0.0.0.0/1 + 128.0.0.0/1 loop, DOSSIER.md); this is the Windows half of
// the same fix, and dialer_other.go is what every OS with neither pin falls
// back to.
//
// THE TRAP: v4 and v6 do not agree on the interface index's byte order (see
// unicastif.go for the full citation), and getting it wrong is silent --
// setsockopt still returns success, it just pins to the wrong interface, or
// to index 0 (unbound) if the wrong-endian value happens to name nothing.
// Either way TUN mode loops exactly as if bindToInterface were never called,
// with no error anywhere to catch it. unicastif_test.go is the regression
// test for that arithmetic, and it runs on every OS -- including whatever
// machine built this change -- specifically because that is the only way to
// actually execute it rather than merely type-check it here.
func bindToInterface(fd uintptr, name string, v6 bool) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("look up interface %q: %w", name, err)
	}
	h := syscall.Handle(fd)
	if v6 {
		if err := syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6UnicastIF, int(unicastIFIndexV6(ifi.Index))); err != nil {
			return fmt.Errorf("IPV6_UNICAST_IF %s (index %d): %w", name, ifi.Index, err)
		}
		return nil
	}
	if err := syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipUnicastIF, int(unicastIFIndexV4(ifi.Index))); err != nil {
		return fmt.Errorf("IP_UNICAST_IF %s (index %d): %w", name, ifi.Index, err)
	}
	return nil
}
