//go:build !windows

package cliapp

import (
	"fmt"
	"io"

	"github.com/mumudevx/dpb/internal/buildinfo"
)

// runCaptureSysconf refuses BY NAME on every platform but Windows, rather
// than silently doing nothing. internal/netwatch/route_other.go and
// internal/emit/stub_other.go both exist to state that same rule for a
// capability a platform genuinely lacks: a stub that compiles, looks
// reachable and quietly no-ops is how a missing capability survives
// undetected, and this command has nothing sensible to fall back to — there
// is no macOS analogue of MibIpForwardTable2 or
// WinHttpGetIEProxyConfigForCurrentUser for it to read instead.
func runCaptureSysconf(_ io.Writer, dir string) error {
	return fmt.Errorf(
		"devtool capture-sysconf reads Win32 APIs (internal/sysconf/scwindows) and is implemented for windows only; this binary is %s, so %s was not written",
		buildinfo.Platform(), dir)
}
