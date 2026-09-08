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
//
// A launchctl that FAILED is an error, including the silent kind. Some launchd
// builds answer an unset variable by exiting non-zero with no output, which is
// indistinguishable from a read that broke — and this is the capture read, so
// guessing "unset" is destructive: launchEnvOp.prepare stores the guess in
// prevSet and Revert then UNSETS a variable the user set themselves. The
// pre-branch code refused the apply outright (46e30d6, op_launchenv.go:105);
// this keeps that refusal and names the ambiguity for the one caller allowed to
// tolerate it, sysport.EnvLookup.
func (c envCtl) Get(ctx context.Context, name string) (string, bool, error) {
	if name == "" {
		return "", false, fmt.Errorf("netstate: launchctl getenv needs a variable name")
	}
	res := c.p.run.Run(ctx, "launchctl", "getenv", name)
	if err := res.Error(); err != nil {
		// res.Err means the command could not be run at all — launchctl
		// missing, or the Runner nil — so it is not even the ambiguous case;
		// nothing about the variable was established either way.
		if res.Err == nil && strings.TrimSpace(res.Combined) == "" {
			return "", false, fmt.Errorf("netstate: launchctl getenv %s: %w (%w)",
				name, err, sysport.ErrEnvUnreadable)
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
// `launchctl getenv`, tolerantly: a variable this machine's launchctl refuses
// to answer for reads as "not set".
//
// launchd's own store is the only place a session environment variable lives,
// so there is no second observer to consult here — the same carve-out
// documented on launchEnvOp. The deeper caveat applies to this reader too: what
// launchd holds affects processes started AFTER it was set, so a value read
// here says nothing about the Electron app that was already running.
//
// It is a shim, deliberately. The launchctl call is expressed once in
// envCtl.Get and the tolerance once in sysport.EnvLookup; this spelling exists
// because scdarwin's own tests read the diagnostic path through it, and because
// netstate.ReadLaunchEnv — the caller `dpb doctor` actually reaches — cannot
// name a darwin-only package.
func ReadLaunchEnv(ctx context.Context, e Env, name string) (string, error) {
	return sysport.EnvLookup(ctx, New(e).Env(), name)
}
