//go:build !windows

package cliapp

import "github.com/mumudevx/dpb/internal/netstate"

// harnessPort is the Port the command harness injects into globals.sys.
//
// On darwin it is nil, which is what the harness did before this seam existed:
// globals.sysOf() then builds the real scdarwin Port over the fakeMac Runner,
// so every darwin test still drives the shipped platform implementation and
// asserts the networksetup/scutil/launchctl argv it issues. Nothing about the
// darwin path changes.
//
// harnessport_windows_test.go returns a real fake there, and its doc comment
// explains why Windows cannot use the same arrangement.
func harnessPort(*fakeMac) netstate.Port { return nil }
