//go:build !darwin

package cliapp

import "github.com/mumudevx/dpb/internal/netstate"

// newSysPort has no platform Port to build here yet: scwindows is Plan 3's
// scope, and until it lands this file is what a non-darwin build of this
// package resolves at compile time in its place. Returning nil keeps
// globals.sysOf's caller working exactly as before this task — every
// netstate.Env still gets Env.Sys explicitly set to nil, which is exactly
// what leaving it unset already meant, so netstate.Env.sys()'s fallback
// (newDefaultPort, which is unsupportedPort outside darwin) still decides at
// call time.
//
// This file, not port_other.go, is where Plan 3 wires internal/sysconf/scwindows
// in: this package's composition root should not have to change shape again
// once that lands, only this function's body.
func newSysPort(netstate.Env) netstate.Port { return nil }
