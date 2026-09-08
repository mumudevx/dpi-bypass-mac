//go:build !windows

package flow

import "syscall"

// setNoDelay disables Nagle. Every desync technique in the ladder depends on
// the segments it writes reaching the wire as separate packets; with Nagle on,
// the kernel would coalesce a fragment with what follows and the split the DPI
// is supposed to see would never exist.
func setNoDelay(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
}
