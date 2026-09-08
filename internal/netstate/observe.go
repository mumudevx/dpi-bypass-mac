package netstate

import (
	"context"

	"github.com/mumudevx/dpb/internal/sysport"
)

// The exported read-only observers.
//
// `dpb doctor` and `dpb coverage` answer questions about the state the system
// is ACTUALLY in — is an auto-proxy URL still pointing at a port nobody is
// listening on, did the environment variables Discord's updater reads survive.
// Answering them with a second reader written in the CLI would mean the tool
// verifies its own mutations with one observer and diagnoses them with another,
// so they go through the same Port the Ops do.
//
// Every one of them is read-only, and every one of them is a wrapper: the logic
// is in the platform implementation, which is why these survive the move to
// Windows without a second copy appearing in cmd/.

// NewRIB returns the kernel routing-table reader for this platform. It is the
// independent verifier for every route mutation: whatever writes routes, this
// reads, and the two never share a code path.
func NewRIB() RIBReader { return newDefaultRIB() }

// CollectFacts reads the machine's network identity: the uplink, its gateway,
// its addresses, the network services and whether a VPN is in the way.
//
// e.SelfIface names the tunnel this run owns, if it has one yet. It is passed
// through because our own capture routes are the same half-default pair a
// WireGuard-style VPN installs, so without it a re-collect classifies dpb as a
// full-tunnel VPN and dpb refuses to run alongside itself.
func CollectFacts(ctx context.Context, e Env) (*Facts, error) {
	return e.sys().Facts().Collect(ctx, e.SelfIface)
}

// ReadProxyState reports the proxy configuration the system will actually use,
// read through a different subsystem than the one that writes it. On macOS that
// is `scutil --proxy` against the dynamic store rather than the preferences
// plist networksetup wrote, which is why it is the verifier for every proxy Op.
func ReadProxyState(ctx context.Context, e Env) (ProxyState, error) {
	return e.sys().Proxy().Live(ctx)
}

// LiveNameservers reports the resolvers the system actually consults, which is
// not necessarily the list stored against a network service.
func LiveNameservers(ctx context.Context, e Env) ([]string, error) {
	return e.sys().DNS().Live(ctx)
}

// ReadLaunchEnv reads one variable out of the user's login session.
//
// A variable that is not set reads as "" with no error: the caller's question
// is "is it set", and a diagnostic that says "could not tell" where it could
// say "no" is one nobody can act on. A command that could not be run at all is
// still an error, because answering "not set" there would report a fact we
// never established.
//
// That tolerance is this reader's, not the Port's. EnvController.Get is the
// capture read and refuses the ambiguity, because the value it returns is what
// Revert restores from and a wrong "unset" there deletes the user's own
// variable. sysport.EnvLookup is where the one is turned into the other.
//
// The deeper caveat, the same one launchEnvOp carries: what launchd holds
// affects processes started AFTER it was set, so a value read here says nothing
// about the Electron app that was already running.
func ReadLaunchEnv(ctx context.Context, e Env, name string) (string, error) {
	return sysport.EnvLookup(ctx, e.sys().Env(), name)
}
