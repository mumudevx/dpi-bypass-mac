//go:build windows

package flow

import "syscall"

// setNoDelay disables Nagle; see the comment in dialer_unix.go for why every
// rung depends on it. Winsock's setsockopt takes a Handle rather than an int,
// which is the whole reason this file exists.
func setNoDelay(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
}
