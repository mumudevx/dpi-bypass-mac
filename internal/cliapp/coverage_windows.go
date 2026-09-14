//go:build windows

package cliapp

// What `dpb coverage` tells a Windows user each of the two levers actually
// reaches.
//
// These were three string literals inline in coverage.go, naming Safari,
// CFNetwork and launchd unconditionally — including in a Windows build, where
// none of the three exists. `dpb coverage` is the command a user runs
// specifically to find out why a program of theirs is not covered, so its
// answer naming the wrong operating system's software is not cosmetic: it makes
// the one diagnostic that is supposed to resolve the question actively
// misleading. Found by reading the Windows build's output during the
// 2026-09-14 triage; see docs/MEASUREMENTS-windows.md.
//
// It is a build-tagged leaf and not a runtime switch because the mechanisms
// themselves already are: readMechanisms reads through internal/sysport, whose
// Windows implementation (internal/sysconf/scwindows) writes the registry
// values below and not the macOS ones. The text has to follow the code that
// runs, not the code that was written first.
const (
	// The Internet Settings proxy values are read by WinINET — Edge, Internet
	// Explorer, and anything hosting either — and by WinHTTP, which is what
	// most .NET and native clients end up on. Chrome and the Electron apps read
	// them too: Chromium's Windows proxy resolver goes through WinHTTP rather
	// than carrying its own settings. Named in that order because it is the
	// order that answers "is MY program covered" fastest.
	systemProxyCovers = "Edge, Chrome, Electron apps, anything on WinINET or WinHTTP"

	// The session-environment lever here is HKCU\Environment, not launchd:
	// see internal/sysconf/scwindows/env.go, which writes that key and
	// broadcasts WM_SETTINGCHANGE. The variables it sets are the same ones —
	// HTTP_PROXY, HTTPS_PROXY, NO_PROXY — and the same class of program reads
	// them, which is why this half of the report is worth having on Windows at
	// all. GT24 is left out of the Windows wording deliberately: that defect
	// was measured against Discord's macOS updater, and this project has not
	// measured its Windows one.
	envMechanismPrefix = "environment "
	envMechanismCovers = "reqwest, curl, Go, Python, Node — anything that reads HTTP(S)_PROXY"
)
