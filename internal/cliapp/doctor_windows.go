//go:build windows

package cliapp

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/paths"
	"github.com/mumudevx/dpb/internal/sysconf/scwindows"
)

// notWritableRemedy is checkPaths' advice on Windows.
//
// It cannot be darwin's sudo/chown text: paths_windows.go's own package
// comment says why — "UAC elevation keeps the SAME user account, so
// %LOCALAPPDATA% resolves to one place whether or not the process is
// elevated, and there is no ownership to hand back" — and Windows has no
// chown at all (paths.go's EnsureDirs skips it whenever UID is -1, which
// paths_windows.go always sets, elevated or not). A locked StateDir here is
// therefore an ACL or antivirus problem, never the ownership one darwin's
// text names, so pointing a user at `sudo chown` would send them looking for
// a command that does not exist on this platform.
func notWritableRemedy(layout paths.Layout) string {
	return "check the folder's permissions (right-click " + layout.StateDir +
		" -> Properties -> Security), and that no other process " +
		"— antivirus, or a stuck dpb.exe — is holding a file inside it open"
}

// proxySystemName names the OS in checkSystemProxy's "is pointed at a dpb
// that is not running" sentence.
func proxySystemName() string { return "Windows" }

// proxyInspectRemedy is checkSystemProxy's advice when netstate.ReadProxyState
// itself fails. scwindows' Proxy().Live reads WinHTTP's resolved configuration
// for THIS USER (or, on the split-account path, the registry hive directly —
// windows.go's Contract 2b), so the by-hand equivalent of `scutil --proxy` is
// the Settings pane, or a read of the same per-user key dpb writes.
//
// It deliberately does NOT name `netsh winhttp show proxy`. That command
// reports the MACHINE-WIDE WinHTTP proxy, which is a different setting in a
// different place: dpb sets per-user Internet Settings (HKCU, or HKU\<SID>)
// and never touches the machine-wide one. A user following that advice while
// dpb's proxy was live would read "Direct access (no proxy server)" and
// conclude dpb had done nothing — a remedy that manufactures the exact wrong
// diagnosis. `reg query` on the key dpb actually writes cannot do that.
func proxyInspectRemedy() string {
	return "open Settings > Network & Internet > Proxy, or run " +
		`reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"` +
		" by hand to see what this user's applications are pointed at " +
		"(`netsh winhttp show proxy` reads the machine-wide WinHTTP proxy, which dpb never sets)"
}

// proxyEnvRemedy is checkProxyEnv's advice when netstate.ReadLaunchEnv itself
// fails to read a variable. There is no launchctl here; scwindows' envCtl
// reads and writes HKCU\Environment (or the interactive user's hive by SID —
// see checkProxyHive), so the by-hand equivalent is a registry or PowerShell
// query of the same key.
func proxyEnvRemedy() string {
	return "run `reg query HKCU\\Environment` or, in PowerShell, " +
		"`[Environment]::GetEnvironmentVariable('HTTPS_PROXY','User')` to see what is exported"
}

// platformChecks adds the two things Task 5's brief names as what a Windows
// user will actually hit: whether --tun's driver is even installed, and
// whether an elevated dpb is about to write an administrator's registry hive
// instead of the console user's.
func platformChecks(paths.Layout) []check {
	return []check{checkWintun(), checkProxyHive()}
}

// checkWintun reports whether the wintun driver can be loaded.
//
// --tun needs it and dpb does not bundle it. internal/front/tunfe's OpenDevice
// (via wireguard/tun's CreateTUN) loads wintun.dll lazily, with exactly these
// two search directories, the first time a user types --tun; probing the same
// load here means the failure is a `dpb doctor` line read before that attempt,
// not a raw "Unable to load library" two wrappers deep the first time it
// matters.
func checkWintun() check {
	c := check{Name: "wintun driver", State: stateOK}
	h, err := windows.LoadLibraryEx("wintun.dll", 0,
		windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		c.State = stateFail
		if errors.Is(err, windows.ERROR_MOD_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			c.Detail = "wintun.dll was not found next to dpb.exe or in System32; " +
				"--tun cannot create its adapter without it"
		} else {
			c.Detail = fmt.Sprintf("wintun.dll could not be loaded: %v", err)
		}
		c.Remedy = "download the wintun driver for your architecture from https://www.wintun.net " +
			"and place wintun.dll next to dpb.exe; proxy mode does not need it"
		return c
	}
	// This was an existence probe, like resolveUserHive's HKU\<SID> open in
	// userhive.go: the point was the answer, not a handle to keep, and
	// FreeLibrary's own failure has nothing this check would do differently
	// with — the driver already proved loadable either way.
	_ = windows.FreeLibrary(h)
	c.Detail = "wintun.dll loads; --tun can create its adapter"
	return c
}

// checkProxyHive surfaces Task 4's failure mode.
//
// On a standard-user-plus-separate-administrator machine, an elevated dpb's
// HKCU is the ADMINISTRATOR's hive, not the signed-in user's — see
// internal/sysconf/scwindows/userhive.go's header for the full failure this
// describes. Before that file existed, a proxy Verify against the wrong hive
// still passed, and dpb reported Ready while the interactive user's browser
// was never touched. This check is the `dpb doctor` line that connects "my
// browser saw nothing" to "you are elevated as a different account", rather
// than leaving a user to discover it by opening regedit themselves.
func checkProxyHive() check {
	c := check{Name: "proxy hive", State: stateOK}
	label, interactive, err := scwindows.HiveStatus()
	if err != nil {
		c.State = stateFail
		c.Detail = err.Error()
		c.Remedy = "dpb cannot tell whose registry hive proxy and environment settings would " +
			"land in; proxy mode's supported install (`dpb service install`, a logon task running " +
			"as the interactive user) never hits this — run unelevated if you can"
		return c
	}
	if interactive {
		c.State = stateWarn
		c.Detail = fmt.Sprintf("elevated as a different account than the signed-in user; "+
			"per-user settings go to %s, not HKCU", label)
		c.Remedy = "check the SIGNED-IN user's browser, not the administrator's; or run dpb " +
			"unelevated — proxy mode needs no elevation at all, only --tun does"
		return c
	}
	c.Detail = fmt.Sprintf("per-user settings go to %s, the signed-in user's own hive", label)
	return c
}
