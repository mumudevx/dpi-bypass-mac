//go:build darwin

package scdarwin

import (
	"context"
	"fmt"
	"strings"

	"github.com/mumudevx/dpb/internal/sysport"
)

// envCtl sets user-session environment variables through launchctl.
//
// Reading them back with `launchctl getenv` is the one documented exception to
// the two-subsystem rule (see sysport.EnvController): launchd's own store is
// the only place a user-session variable lives, so there is no second observer
// to consult.
//
// Caveat worth stating plainly rather than hiding behind a green read-back:
// `launchctl setenv` only affects processes started AFTER the call. A value
// read here says the variable is in launchd's store; it says nothing about the
// already-running Electron apps whose in-process reqwest addon is the reason
// this controller exists. Those pick it up on their next launch, or not at all.
type envCtl struct{ p *port }

var _ sysport.EnvController = envCtl{}

// Get reads one variable. ok is false when the variable is not set; launchctl
// prints nothing and exits 0 for that case.
func (c envCtl) Get(ctx context.Context, name string) (string, bool, error) {
	if name == "" {
		return "", false, fmt.Errorf("netstate: launchctl getenv needs a variable name")
	}
	res := c.p.run.Run(ctx, "launchctl", "getenv", name)
	if err := res.Error(); err != nil {
		// An unset variable is not an error on every launchd build: some exit
		// non-zero with no output at all. Report THAT as "unset", because the
		// caller's question is "is it set" and a diagnostic that says "could
		// not tell" where it could say "no" is one nobody can act on.
		//
		// res.Err is the exception. It means the command could not be run —
		// launchctl missing, or the Runner nil — and answering "not set" there
		// would report a fact we never established.
		if res.Err == nil && strings.TrimSpace(res.Combined) == "" {
			return "", false, nil
		}
		return "", false, fmt.Errorf("netstate: launchctl getenv %s: %w", name, err)
	}
	val := strings.TrimSpace(res.Combined)
	return val, val != "", nil
}

func (c envCtl) Set(ctx context.Context, name, value string) error {
	return c.p.run.Run(ctx, "launchctl", "setenv", name, value).Error()
}

func (c envCtl) Unset(ctx context.Context, name string) error {
	return c.p.run.Run(ctx, "launchctl", "unsetenv", name).Error()
}

// ReadLaunchEnv reads one variable out of the user's launchd session with
// `launchctl getenv`.
//
// launchd's own store is the only place a session environment variable lives,
// so there is no second observer to consult here — the same carve-out
// documented on launchEnvOp. The deeper caveat applies to this reader too: what
// launchd holds affects processes started AFTER it was set, so a value read
// here says nothing about the Electron app that was already running.
func ReadLaunchEnv(ctx context.Context, e Env, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("netstate: launchctl getenv needs a variable name")
	}
	res := e.runner().Run(ctx, "launchctl", "getenv", name)
	if err := res.Error(); err != nil {
		// An unset variable is not an error on every launchd build: some exit
		// non-zero with no output at all. Report THAT as "unset", because the
		// caller's question is "is it set" and a diagnostic that says "could
		// not tell" where it could say "no" is one nobody can act on.
		//
		// res.Err is the exception. It means the command could not be run —
		// launchctl missing, or Env.Runner nil — and answering "not set" there
		// would report a fact we never established.
		if res.Err == nil && strings.TrimSpace(res.Combined) == "" {
			return "", nil
		}
		return "", fmt.Errorf("netstate: launchctl getenv %s: %w", name, err)
	}
	return strings.TrimSpace(res.Combined), nil
}
