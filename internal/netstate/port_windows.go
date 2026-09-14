//go:build windows

package netstate

import "github.com/mumudevx/dpb/internal/sysconf/scwindows"

// newDefaultPort builds the Windows Port out of this Env.
//
// It mirrors port_darwin.go exactly, and for the same reasons: the Env's own
// RIB goes in because it is the independent verifier, and substituting IP
// Helper's own reader for an injected one would make every test that supplies a
// routing table read the real machine instead; the logger goes in because Facts
// collection and the best-effort teardown paths record what they could not do
// rather than failing on it, and a Port with nowhere to log would drop those
// lines from `dpb doctor`.
//
// scwindows.Env is not netstate.Env — scwindows cannot import netstate, which
// is the import cycle sysport exists to prevent — but it carries the same three
// fields, so this is a relabel and not a translation that could drop one.
func newDefaultPort(e Env) Port {
	return scwindows.New(scwindows.Env{Runner: e.runner(), RIB: e.RIB, Logf: e.Logf})
}

// newDefaultRIB is the kernel routing-table reader on its own, for a caller
// that wants the verifier before it has an Env to put it in. As on darwin it is
// deliberately NOT the fallback inside newDefaultPort: an Env with no RIB must
// stay an Env with no RIB, because "collect facts without a RIB" is an error
// callers rely on rather than an invitation to go and read the real table.
func newDefaultRIB() RIBReader { return scwindows.NewRIB() }
