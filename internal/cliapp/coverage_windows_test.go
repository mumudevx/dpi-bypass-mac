//go:build windows

package cliapp

import (
	"strings"
	"testing"
)

// TestCoverageReportsBothMechanismsAndWhoTheyCoverOnWindows is
// coverage_darwin_test.go's test of the same name for the two levers Windows
// actually has.
//
// The property is the one GT24 bought: the two mechanisms cover DIFFERENT
// classes of program and the report has to say which, because "PAC is on"
// means nothing to a user trying to work out why an updater still cannot
// connect. The names are Windows' own — WinINET/WinHTTP rather than CFNetwork,
// "environment HTTPS_PROXY" rather than "launchd HTTPS_PROXY" — and they are
// written out as literals rather than taken from coverage_windows.go's
// constants on purpose: using the constants would pin each assertion to itself
// and let a rename pass unnoticed, which is the same rule
// TestProxyStateFromIETranslatesToScutilKeys states for the key names.
func TestCoverageReportsBothMechanismsAndWhoTheyCoverOnWindows(t *testing.T) {
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
	// Edge, Chrome and the Electron apps all reach the Internet Settings proxy
	// through WinINET or WinHTTP; naming the API is what lets a user decide
	// whether their own program is in that set.
	if !strings.Contains(pac.Covers, "WinINET") {
		t.Errorf("the PAC mechanism does not say who it covers: %q", pac.Covers)
	}
	env := findMechanism(t, rep, "environment HTTPS_PROXY")
	if !env.Set {
		t.Fatalf("the environment mechanism = %+v", env)
	}
	// The class of program is what this half exists for, and on Windows it is
	// named by the libraries rather than by Discord's updater: GT24 was
	// measured against the macOS build and this project has not measured the
	// Windows one, which coverage_windows.go says out loud.
	if !strings.Contains(env.Covers, "HTTP(S)_PROXY") {
		t.Errorf("the environment mechanism does not name what reads it: %q", env.Covers)
	}
}

// TestCoverageShowsOneLeverSetAndTheOtherNotOnWindows: setting one lever and
// not the other leaves a whole class of program uncovered, and the report has
// to make that visible side by side.
func TestCoverageShowsOneLeverSetAndTheOtherNotOnWindows(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "networksetup", "-setautoproxyurl", "Wi-Fi", "http://127.0.0.1:8080/dpb.pac")

	rep, _ := coverageJSON(t, c)
	if !findMechanism(t, rep, "auto-proxy URL (PAC)").Set {
		t.Error("the PAC was reported as unset")
	}
	if findMechanism(t, rep, "environment HTTPS_PROXY").Set {
		t.Error("an unset environment variable was reported as set")
	}
}

// TestCoverageNamesNoMacOSSoftwareOnWindows is the defect the 2026-09-14
// triage found, pinned so it cannot come back: before coverage_windows.go the
// Windows build reported Safari, CFNetwork and launchd, none of which exists
// on the platform, in the one diagnostic whose whole job is to resolve "why is
// MY program not covered".
func TestCoverageNamesNoMacOSSoftwareOnWindows(t *testing.T) {
	c := newCLI(t)
	rep, _ := coverageJSON(t, c)
	if len(rep.Mechanisms) == 0 {
		t.Fatal("the report named no mechanisms at all")
	}
	for _, m := range rep.Mechanisms {
		for _, bad := range []string{"CFNetwork", "launchd", "Safari"} {
			if strings.Contains(m.Name, bad) || strings.Contains(m.Covers, bad) {
				t.Errorf("mechanism %q names %s, which does not exist on Windows: %q",
					m.Name, bad, m.Covers)
			}
		}
	}
}

// TestHarnessPortDNSMatchesTheFakeScutil is the drift guard the tun bring-up
// sequence needs: it installs one /32 host route per system resolver, reading
// them through LiveNameservers, and on darwin that answer comes from fakeMac's
// `scutil --dns` text while on Windows it comes from harnessSysPort. If the two
// disagree the Windows fixture quietly plans one route fewer than the darwin
// one, which is exactly the failure the 2026-09-14 run showed (5 Ops applied,
// 6 wanted).
func TestHarnessPortDNSMatchesTheFakeScutil(t *testing.T) {
	f := newFakeMac()
	out := f.Run(t.Context(), "scutil", "--dns")
	if !strings.Contains(out.Combined, fakeMacLiveResolver) {
		t.Fatalf("fakeMac's `scutil --dns` answer does not name %s:\n%s",
			fakeMacLiveResolver, out.Combined)
	}
	got, err := harnessPort(f).DNS().Live(t.Context())
	if err != nil {
		t.Fatalf("DNS().Live: %v", err)
	}
	if len(got) != 1 || got[0] != fakeMacLiveResolver {
		t.Fatalf("DNS().Live = %v, want [%s] so both platforms' fixtures model the same machine",
			got, fakeMacLiveResolver)
	}
}
