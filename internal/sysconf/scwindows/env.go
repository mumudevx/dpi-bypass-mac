//go:build windows

package scwindows

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mumudevx/dpb/internal/sysport"
)

// envCtl sets user-session environment variables in HKCU\Environment and
// broadcasts WM_SETTINGCHANGE so already-running processes with a message
// loop notice the change.
//
// Reading a value back with registry.Key.GetStringValue, straight out of the
// same key Set and Unset write, is this package's one documented exception
// to Contract 1's "verify through a different subsystem" rule — the same
// carve-out scdarwin.envCtl states for `launchctl setenv`/`getenv`:
// HKCU\Environment is the only place a user-session environment variable
// lives, so there is no second observer to consult. What makes that
// tolerable rather than a mirror of the write is that the registry, unlike
// launchctl's text protocol, gives an unambiguous, typed answer for
// "this was never set" (registry.ErrNotExist) versus every other failure —
// see Get below.
//
// Caveat carried over verbatim from scdarwin.envCtl, restated for the
// mechanism that makes it true here: a value written to HKCU\Environment
// only reaches processes started AFTER the write. A value read back here, or
// a passing Verify (internal/netstate/op_launchenv.go), says the registry
// holds the value; it says nothing about the already-running Electron apps
// whose in-process reqwest addon is the reason this controller exists. Those
// pick it up on their next launch, via a fresh CreateProcess reading a fresh
// copy of HKCU\Environment, or not at all. WM_SETTINGCHANGE narrows that gap
// for processes that are both already running AND already listening for it
// (Explorer, and anything else with a message loop that reacts to the
// broadcast) — it does not close it.
type envCtl struct{ p *port }

var _ sysport.EnvController = envCtl{}

// environmentKey is where a user's session environment variables live, under
// HKCU. HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
// holds the SYSTEM-wide set instead; this package never touches that hive,
// because a proxy override dpb installs belongs to the user account running
// dpb, not to every account on the machine.
//
// # KNOWN LIMITATION: HKCU here is the ELEVATED token's hive
//
// Every registry.CURRENT_USER open in this file resolves through the ACCESS
// TOKEN OF THE CALLING PROCESS — MSDN, "Predefined Keys". dpb requires
// elevation on Windows, so on the enterprise-default machine — a standard user
// account plus a SEPARATE administrator account, where UAC asks for the
// admin's credentials rather than consent — "the user account running dpb" in
// the paragraph above is the ADMIN, and HTTP_PROXY / HTTPS_PROXY / NO_PROXY
// are written into the ADMIN's environment.
//
// Get reads that same hive, so Verify passes; the interactive user's own
// applications inherit nothing, because CreateProcess builds their environment
// from the hive of the user who launched them. Nothing is left broken on the
// way out — the revert is equally invisible — but nothing was ever done
// either, and dpb says Ready throughout. proxy.go's internetSettingsKey
// carries the identical limitation for Internet Settings, and the fix is the
// same substantial piece of work described there (WTSQueryUserToken on the
// active session, then that user's hive). It is deliberately NOT attempted
// here, and it is the top item for the first session on a real Windows
// machine.
const environmentKey = `Environment`

// Get reads one variable's value straight out of HKCU\Environment.
//
// ok is false ONLY when registry.ErrNotExist says the value has never been
// written — the registry's own POSITIVE statement that there is nothing
// here, the same reading proxy.go's regString gives it for a missing
// Internet Settings value. Any OTHER error — permission denied, a value
// whose type GetStringValue cannot read as a plain string
// (registry.ErrUnexpectedType), the Environment key itself missing — is
// returned as an error and is NEVER read as "unset".
//
// That distinction is the one this whole function exists to enforce, and
// Plan 2 already shipped its absence once and had to revert it. darwin's
// envCtl.Get originally treated a failed `launchctl getenv` as "unset";
// launchEnvOp.prepare (internal/netstate/op_launchenv.go) stored that guess
// in prevSet, and Revert then ran `launchctl unsetenv` on every name
// recorded that way — deleting a user's own pre-existing HTTPS_PROXY on the
// way out. The fix was sysport.EnvController.Get's current contract (see its
// doc comment there) plus sysport.ErrEnvUnreadable for the one caller,
// EnvLookup, that is allowed to tolerate the ambiguity launchctl's text
// protocol has and the registry does not. This function has no ambiguous
// case to mark: registry.ErrNotExist is unambiguous, so it never wraps
// ErrEnvUnreadable at all.
//
// ok = true whenever the value exists, even if it is the empty string — a
// STRONGER signal than scdarwin.envCtl.Get can give, which ties ok to
// whether launchctl printed anything because launchctl's text protocol
// cannot otherwise tell "set to empty" from "not set". The registry's own
// key-exists/key-absent distinction does not have that limitation, so this
// does not manufacture one.
func (c envCtl) Get(_ context.Context, name string) (string, bool, error) {
	if name == "" {
		return "", false, fmt.Errorf("netstate: HKCU\\%s needs a variable name", environmentKey)
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, environmentKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			// No Environment key at all is the same positive "never set" the
			// registry gives a missing VALUE — see the case below — not a
			// reason to fail the read. Every interactive user session has one
			// in practice; this only matters for a service account or a
			// stripped test profile, and treating it as "unreadable" there
			// would refuse a capture over a machine shape that is not this
			// tool's problem.
			return "", false, nil
		}
		return "", false, fmt.Errorf("netstate: open HKCU\\%s: %w", environmentKey, err)
	}
	defer key.Close()

	val, _, err := key.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("netstate: read HKCU\\%s\\%s: %w", environmentKey, name, err)
	}
	return val, true, nil
}

// Set writes name=value into HKCU\Environment and broadcasts
// WM_SETTINGCHANGE. See broadcastEnvironmentChange for why a failed or slow
// broadcast is logged rather than returned as an error here.
func (c envCtl) Set(_ context.Context, name, value string) error {
	if name == "" {
		return fmt.Errorf("netstate: HKCU\\%s needs a variable name", environmentKey)
	}
	// CreateKey rather than OpenKey, matching proxy.go's openInternetSettings:
	// it opens the existing key on every real interactive session, and on the
	// one where it is somehow absent this makes it rather than failing an
	// Apply the user asked for.
	key, _, err := registry.CreateKey(registry.CURRENT_USER, environmentKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("netstate: open HKCU\\%s for writing: %w", environmentKey, err)
	}
	defer key.Close()

	if err := key.SetStringValue(name, value); err != nil {
		return fmt.Errorf("netstate: set HKCU\\%s\\%s: %w", environmentKey, name, err)
	}
	broadcastEnvironmentChange(c.p.env().logf)
	return nil
}

// Unset removes name from HKCU\Environment and broadcasts
// WM_SETTINGCHANGE. A value, or the whole key, that is already absent is
// success rather than a failure to tidy — the same idiom proxy.go's
// restoreAutoConfigURL and restoreProxyServer use for DeleteValue.
func (c envCtl) Unset(_ context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("netstate: HKCU\\%s needs a variable name", environmentKey)
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, environmentKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			// No Environment key at all means there is nothing to unset.
			broadcastEnvironmentChange(c.p.env().logf)
			return nil
		}
		return fmt.Errorf("netstate: open HKCU\\%s for writing: %w", environmentKey, err)
	}
	defer key.Close()

	if err := key.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("netstate: delete HKCU\\%s\\%s: %w", environmentKey, name, err)
	}
	broadcastEnvironmentChange(c.p.env().logf)
	return nil
}

// The four WM_SETTINGCHANGE broadcast constants, from winuser.h. They are
// spelled out here rather than imported because golang.org/x/sys/windows
// does not carry Win32 window-message constants (it is a syscall package,
// not a UI one) — the same reason proxy.go declares its own wininet option
// numbers instead of finding them in x/sys.
const (
	// HWND_BROADCAST: "#define HWND_BROADCAST ((HWND)0xffff)" — send to every
	// top-level window rather than one specific one.
	hwndBroadcast = 0xffff
	// WM_SETTINGCHANGE: "#define WM_SETTINGCHANGE WM_WININICHANGE" and
	// "#define WM_WININICHANGE 0x001A".
	wmSettingChange = 0x001A
	// SMTO_ABORTIFHUNG: do not wait out the timeout against a window Windows
	// has already given up on for being hung — only a window that is merely
	// slow to respond pays the timeout below.
	smtoAbortIfHung = 0x0002
	// settingsBroadcastTimeoutMS bounds how long this waits for EACH
	// top-level window to answer, not the broadcast as a whole: MSDN
	// documents HWND_BROADCAST as visiting every top-level window in turn and
	// applying uTimeout PER WINDOW, so a desktop with many top-level windows
	// pays this cost that many times over on a single Set or Unset — and
	// internal/netstate/op_launchenv.go's Revert calls Unset up to three
	// times (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) on the Ctrl-C path. A
	// registry-settings-change notification is cheap for a responsive window
	// procedure to answer; 500ms is short enough that teardown stays
	// responsive even against several slow-but-not-hung windows, which is the
	// property this whole function exists to protect — a hung window must
	// not stall teardown.
	settingsBroadcastTimeoutMS = 500
)

// broadcastEnvironmentChange tells already-running processes with a message
// loop that HKCU\Environment changed. It is best-effort: a failure or a
// timeout here is LOGGED, never returned as an error from Set or Unset.
//
// Two reasons, not one, and either alone would justify it. First, the
// registry write Set/Unset just made is the durable state a freshly-started
// process's CreateProcess actually inherits, and that does not depend on any
// window answering this broadcast. Second, and the reason this is not merely
// an optimisation: Get in this file reads HKCU\Environment directly, so a
// failed or slow broadcast changes nothing about what Get — and therefore
// Verify, internal/netstate/op_launchenv.go — will report either way.
// Hard-failing Set or Unset over it would report a real, durable write as
// broken because some unrelated top-level window on the user's desktop was
// slow to answer a message, and it would do that on the Ctrl-C path, where
// Revert calls Unset for every variable it captured — turning a revert that
// is, in the only sense this package can verify, complete, into one
// netstate reports as failed.
//
// This is a deliberate asymmetry with proxy.go's notifyProxyChanged, which
// DOES return its failure. That is the right call there because Live
// (proxy.go) reads the RESOLVED configuration through WinHTTP rather than
// mirroring the registry write, so a silently-failed notification there
// really would let a Verify pass while nothing is actually proxied — the
// exact failure mode this paragraph just argued does not exist for Get here.
func broadcastEnvironmentChange(logf func(string, ...any)) {
	param, err := environmentChangeLParam()
	if err != nil {
		// Unreachable for this literal — it carries no NUL byte — but handled
		// rather than ignored, so a future edit that turns this into a
		// variable cannot silently start dereferencing a nil pointer.
		logf("netstate: encode WM_SETTINGCHANGE's lParam: %v", err)
		return
	}

	var result uintptr
	// param is passed as the *uint16 it is: the unsafe.Pointer→uintptr
	// conversion has to happen inside LazyProc.Call's own argument list for
	// //go:uintptrescapes to keep the string alive across the syscall, and
	// converting it here — one frame up — would not. See SendMessageTimeoutW.
	if err := SendMessageTimeoutW(
		hwndBroadcast, wmSettingChange, 0, param,
		smtoAbortIfHung, settingsBroadcastTimeoutMS, &result,
	); err != nil {
		logf("netstate: broadcast WM_SETTINGCHANGE for HKCU\\Environment: %v "+
			"(already-running processes may not notice until they restart)", err)
	}
}

// environmentChangeLParam is WM_SETTINGCHANGE's lParam for this broadcast,
// split out of broadcastEnvironmentChange as its own function for the same
// reason iface.go splits out setUnicastRow and route.go splits out routeRow:
// it is the one piece of an otherwise real-syscall-dependent function that a
// test can call without a Windows host to run SendMessageTimeoutW against.
//
// MSDN is explicit about the value: "To effect a change in the environment
// variables for the system or the user, broadcast this message with lParam
// set to the string 'Environment'." See
// https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-settingchange
func environmentChangeLParam() (*uint16, error) {
	return windows.UTF16PtrFromString("Environment")
}
