//go:build darwin

package netstate

import "github.com/mumudevx/dpb/internal/sysconf/scdarwin"

// newDefaultPort builds the macOS Port out of this Env.
//
// The Env's own RIB and Logf go in, not just the Runner. The RIB because it is
// the independent verifier and substituting the kernel's for an injected one
// would make every test read the real machine; the logger because Facts
// collection records what it could not read rather than failing on it, and a
// Port with nowhere to log would drop those lines from `dpb doctor`.
func newDefaultPort(e Env) Port {
	return scdarwin.New(scdarwin.Env{Runner: e.runner(), RIB: e.RIB, Logf: e.Logf})
}

// newDefaultRIB is the kernel routing-table reader on its own, for a caller
// that wants the verifier before it has an Env to put it in. It is deliberately
// NOT the fallback inside newDefaultPort: an Env with no RIB must stay an Env
// with no RIB, because "collect facts without a RIB" is an error callers rely
// on rather than an invitation to go and read the real table.
func newDefaultRIB() RIBReader { return scdarwin.NewRIB() }
