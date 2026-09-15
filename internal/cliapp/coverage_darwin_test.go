//go:build darwin

// The two `dpb coverage` tests that assert macOS's names for the two levers.
//
// What they assert that Windows cannot express: the NAMES, and deliberately
// so. `dpb coverage` is the command a user runs to find out why a particular
// program of theirs is not covered, so its answer has to name that platform's
// software: coverage_darwin.go says the system proxy reaches "Safari, Chrome,
// Electron apps, anything on CFNetwork" and calls the session lever "launchd
// HTTPS_PROXY", while coverage_windows.go says "Edge, Chrome, Electron apps,
// anything on WinINET or WinHTTP" and "environment HTTPS_PROXY" — because on
// Windows there is no CFNetwork and no launchd, and a report naming them was
// the defect the 2026-09-14 triage found by reading the Windows build's output.
//
// So these two cannot be shared, and must not be: a version with the names
// factored out through the same constants the code uses would pin each
// assertion to itself and assert nothing. coverage_windows_test.go asserts the
// same two PROPERTIES — that each mechanism says who it covers, and that one
// lever set with the other unset is reported side by side — against the
// Windows names written out as literals.
//
// Both function bodies are unchanged from coverage_test.go, where they lived
// until the Windows suite started running. They keep using coverageJSON and
// findMechanism from that file, which carries no build tag.

package cliapp

import (
	"strings"
	"testing"
)

// The two mechanisms cover DIFFERENT classes of program, and the report has to
// say which. "PAC is on" means nothing to a user trying to work out why
// Discord's updater still cannot connect (GT24).
func TestCoverageReportsBothMechanismsAndWhoTheyCover(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "networksetup", "-setautoproxyurl", "Wi-Fi", "http://127.0.0.1:8080/dpb.pac")
	c.mac.Run(t.Context(), "launchctl", "setenv", "HTTPS_PROXY", "http://127.0.0.1:8080")

	rep, r := coverageJSON(t, c)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	pac := findMechanism(t, rep, "auto-proxy URL (PAC)")
	if !pac.Set || pac.Value != "http://127.0.0.1:8080/dpb.pac" {
		t.Fatalf("PAC mechanism = %+v", pac)
	}
	if !strings.Contains(pac.Covers, "CFNetwork") {
		t.Errorf("the PAC mechanism does not say who it covers: %q", pac.Covers)
	}
	env := findMechanism(t, rep, "launchd HTTPS_PROXY")
	if !env.Set {
		t.Fatalf("the environment mechanism = %+v", env)
	}
	if !strings.Contains(env.Covers, "updater") {
		t.Errorf("the environment mechanism does not name the program it exists for: %q", env.Covers)
	}
}

// Setting one lever and not the other leaves a whole class of program
// uncovered, and the report has to make that visible side by side.
func TestCoverageShowsOneLeverSetAndTheOtherNot(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "networksetup", "-setautoproxyurl", "Wi-Fi", "http://127.0.0.1:8080/dpb.pac")

	rep, _ := coverageJSON(t, c)
	if !findMechanism(t, rep, "auto-proxy URL (PAC)").Set {
		t.Error("the PAC was reported as unset")
	}
	if findMechanism(t, rep, "launchd HTTPS_PROXY").Set {
		t.Error("an unset environment variable was reported as set")
	}
}
