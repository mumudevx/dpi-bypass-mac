//go:build darwin

package cliapp

import (
	"fmt"

	"github.com/mumudevx/dpb/internal/paths"
)

// notWritableRemedy is checkPaths' advice when the state directory exists but
// this process cannot write to it.
//
// This is the sudo/chown trap doctor.go's package comment and checkPaths'
// doc comment both describe: `sudo dpb run --tun` leaves the journal owned by
// root, and every unprivileged command afterwards — including the repair
// that would fix it — cannot touch its own files. This text is unchanged
// from what checkPaths inlined before Task 5 split it out, so darwin's
// behaviour is identical to before.
func notWritableRemedy(layout paths.Layout) string {
	if !layout.Elevated {
		return fmt.Sprintf("a previous `sudo dpb` may own it: sudo chown -R %s %s",
			layout.User, layout.StateDir)
	}
	return "check the permissions on " + layout.StateDir
}

// proxySystemName names the OS in checkSystemProxy's "is pointed at a dpb
// that is not running" sentence.
func proxySystemName() string { return "macOS" }

// proxyInspectRemedy is checkSystemProxy's advice when netstate.ReadProxyState
// itself fails (not when it succeeds and finds residue — that has its own,
// platform-neutral remedy naming `dpb doctor --repair`).
func proxyInspectRemedy() string {
	return "run `scutil --proxy` by hand to see what macOS is pointed at"
}

// proxyEnvRemedy is checkProxyEnv's advice when netstate.ReadLaunchEnv itself
// fails to read a variable (not when it succeeds and finds one stale — that
// has its own, platform-neutral remedy naming `dpb doctor --repair`).
func proxyEnvRemedy() string {
	return "run `launchctl getenv HTTPS_PROXY` by hand to see what is exported"
}

// platformChecks is darwin's contribution to `dpb doctor`'s audit beyond the
// checks collectChecks already runs on every platform.
//
// There is none. Every darwin-specific fact this command reports — the
// system proxy, the launchd session environment — is already covered by
// checkSystemProxy and checkProxyEnv, which read through netstate's
// platform-neutral Port; returning nil here is what keeps `dpb doctor` on
// darwin producing EXACTLY the checks it produced before Task 5, in the same
// order, which is what doctor_test.go asserts.
func platformChecks(paths.Layout) []check { return nil }
