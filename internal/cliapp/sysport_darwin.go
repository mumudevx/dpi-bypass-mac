//go:build darwin

package cliapp

import (
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/sysconf/scdarwin"
)

// newSysPort builds the macOS Port from e's Runner, RIB and Logf.
//
// scdarwin.Env is not netstate.Env — scdarwin cannot import netstate, which
// is the import cycle sysport exists to prevent — but it carries the same
// three fields, so this is a straight relabel, not a translation that could
// drop something.
func newSysPort(e netstate.Env) netstate.Port {
	return scdarwin.New(scdarwin.Env{Runner: e.Runner, RIB: e.RIB, Logf: e.Logf})
}
