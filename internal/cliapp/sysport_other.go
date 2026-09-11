//go:build !darwin && !windows

package cliapp

import "github.com/mumudevx/dpb/internal/netstate"

// newSysPort has no platform Port to build on the remaining GOOS values: dpb
// ships scdarwin and scwindows (sysport_darwin.go and sysport_windows.go),
// and nothing else. Returning nil keeps globals.sysOf's caller working
// exactly as it does on darwin and windows — every netstate.Env still gets
// Env.Sys explicitly set, here to nil, which is exactly what leaving it
// unset already meant, so netstate.Env.sys()'s fallback (newDefaultPort,
// which is unsupportedPort outside darwin and windows) still decides at call
// time.
func newSysPort(netstate.Env) netstate.Port { return nil }
