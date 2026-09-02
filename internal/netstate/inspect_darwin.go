package netstate

import (
	"context"
	"fmt"
	"strings"
)

// The exported read-only observers.
//
// The scutil and launchctl readers in this package are the independent
// verifiers Op.Verify uses, and they were unexported because nothing outside
// netstate needed them. `dpb doctor` and `dpb coverage` do: both answer
// questions about the state macOS is ACTUALLY in — is an auto-proxy URL still
// pointing at a port nobody is listening on, did the environment variables
// Discord's updater reads survive — and answering them with a second parser
// written in the CLI would mean the tool verifies its own mutations with one
// reader and diagnoses them with another.
//
// These are wrappers, not new logic, and every one of them is read-only.

// ReadProxyState runs `scutil --proxy` and parses it. It reads the dynamic
// store the system actually consults, not the preferences plist networksetup
// wrote, which is why it is the verifier for every proxy Op.
func ReadProxyState(ctx context.Context, e Env) (ProxyState, error) {
	return readProxyState(ctx, e)
}

// ReadDNSResolvers runs `scutil --dns` and parses the resolver blocks.
func ReadDNSResolvers(ctx context.Context, e Env) ([]DNSResolver, error) {
	return readDNSResolvers(ctx, e)
}

// PrimaryNameservers is the unscoped resolver list, which is what an ordinary
// lookup on this machine uses.
func PrimaryNameservers(rs []DNSResolver) []string { return primaryNameservers(rs) }

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
