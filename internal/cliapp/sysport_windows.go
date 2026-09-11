//go:build windows

package cliapp

import (
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/sysconf/scwindows"
)

// newSysPort builds the Windows Port from e's Runner, RIB and Logf.
//
// scwindows.Env is not netstate.Env — scwindows cannot import netstate, which
// is the import cycle sysport exists to prevent — but it carries the same
// three fields, so this is a straight relabel, not a translation that could
// drop something. See sysport_darwin.go's newSysPort for the identical shape
// on the other platform.
func newSysPort(e netstate.Env) netstate.Port {
	return scwindows.New(scwindows.Env{Runner: e.Runner, RIB: e.RIB, Logf: e.Logf})
}
