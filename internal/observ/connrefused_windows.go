//go:build windows

package observ

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isConnRefused reports whether err is Winsock refusing a connect because
// nothing is accepting on the socket.
//
// # Why syscall.ECONNREFUSED cannot be used here
//
// It EXISTS on Windows, it compiles, and it can never match. Go defines the
// whole POSIX E* block on Windows as synthetic values for its own emulated
// syscalls, allocated out of APPLICATION_ERROR: $GOROOT/src/syscall/
// zerrors_windows.go opens that block with `E2BIG Errno = APPLICATION_ERROR +
// iota` (APPLICATION_ERROR = 1<<29) and lists ECONNREFUSED among them, with
// its string table keyed by `ECONNREFUSED - APPLICATION_ERROR`. Winsock never
// returns one of those. A refused connect returns WSAECONNREFUSED, 10061.
//
// So `errors.Is(err, syscall.ECONNREFUSED)` in dial() was dead code, and it was
// dead in the one place it mattered most: the comment beside it names what it
// is for — "the file survived a SIGKILL but nothing is accepting on it" — so on
// Windows dpb could not recognise a stale control socket at all. Measured on
// windows-latest, 2026-09-14: `dpb off`, `dpb panic`, `dpb coverage --fix` and
// `dpb _janitor` each printed the raw Winsock sentence where they should have
// said "no dpb is running", and TestClientReportsNotRunning failed outright.
// See docs/MEASUREMENTS-windows.md.
//
// # os.ErrNotExist does not cover the gap either
//
// dial() also accepts os.ErrNotExist for "no socket file at all", and on Unix
// that is the common case. On Windows it is not reached: the same CI run dialled
// a path with NOTHING bound and still got WSAECONNREFUSED rather than
// ERROR_FILE_NOT_FOUND, because Windows' AF_UNIX reports a missing bind path as
// a refusal. This one errno therefore carries both halves of "not running"
// there, which is why it must be right.
func isConnRefused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }
