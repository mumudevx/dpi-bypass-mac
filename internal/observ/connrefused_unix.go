//go:build !windows

package observ

import (
	"errors"
	"syscall"
)

// isConnRefused reports whether err is the kernel refusing a connect because
// nothing is accepting on the socket.
//
// On Unix that is one errno. connect(2) on a AF_UNIX path whose FILE still
// exists — the shape a SIGKILL leaves behind — with no process accepting on it
// answers ECONNREFUSED, and nothing else does. This is the check dial() has
// always made; it moved into a leaf because its Windows twin cannot be the same
// expression (see connrefused_windows.go).
func isConnRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
