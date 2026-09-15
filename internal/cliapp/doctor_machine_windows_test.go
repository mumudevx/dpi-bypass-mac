//go:build windows

package cliapp

import (
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/paths"
)

// The two Windows platform checks, driven against the real machine.
//
// They are tested here rather than through the command harness because they
// have nothing the harness can inject: checkWintun calls LoadLibraryEx and
// checkProxyHive calls scwindows.HiveStatus(), and both answer about the
// machine the test binary is running on. The harness stands in for them
// precisely so the doctor tests can be about dpb's residue instead (see
// harnessmachine_windows_test.go), which would leave these two with no test at
// all — so they get one that asserts what is true of ANY machine rather than
// of the CI runner.

// TestCheckWintunReportsEitherAnswerWithARemedy pins the shape of the answer,
// not the answer: a GitHub-hosted runner has no wintun.dll and a developer's
// machine may well have one, and both are legitimate.
//
// What must hold either way is that a FAILURE carries a remedy naming where to
// get the driver, and says that proxy mode does not need it. `--tun` is the
// minority mode — MEASUREMENTS.md §3 records the unprivileged emitters beating
// this DPI — so a user who only wants proxy mode must not read this line as
// "dpb does not work here".
func TestCheckWintunReportsEitherAnswerWithARemedy(t *testing.T) {
	c := checkWintun()
	if c.Name != "wintun driver" {
		t.Fatalf("check name = %q", c.Name)
	}
	switch c.State {
	case stateOK:
		if !strings.Contains(c.Detail, "wintun.dll") {
			t.Errorf("a loadable driver is reported as %q", c.Detail)
		}
		if c.Remedy != "" {
			t.Errorf("a passing check carries a remedy: %q", c.Remedy)
		}
	case stateFail:
		if !strings.Contains(c.Detail, "wintun.dll") {
			t.Errorf("detail = %q, want it to name the library", c.Detail)
		}
		if !strings.Contains(c.Remedy, "wintun.net") {
			t.Errorf("remedy = %q, want it to name where the driver comes from", c.Remedy)
		}
		if !strings.Contains(c.Remedy, "proxy mode does not need it") {
			t.Errorf("remedy = %q, want it to say proxy mode is unaffected", c.Remedy)
		}
	default:
		t.Fatalf("state = %q, want ok or fail", c.State)
	}
	t.Logf("wintun driver on this machine: %s — %s", c.State, c.Detail)
}

// TestCheckProxyHiveNamesTheHiveItWouldWrite. The check exists to connect "my
// browser saw nothing" to "you are elevated as a different account", so the
// one thing it must always do is name the hive. A warn — the split-account
// case — additionally has to point the user at the SIGNED-IN user's browser,
// because checking the administrator's is what makes the failure invisible.
func TestCheckProxyHiveNamesTheHiveItWouldWrite(t *testing.T) {
	c := checkProxyHive()
	if c.Name != "proxy hive" {
		t.Fatalf("check name = %q", c.Name)
	}
	if c.Detail == "" {
		t.Fatal("the check says nothing about whose hive would be written")
	}
	switch c.State {
	case stateOK:
		if !strings.Contains(c.Detail, "HKCU") {
			t.Errorf("detail = %q, want it to name the hive", c.Detail)
		}
	case stateWarn:
		if !strings.Contains(c.Remedy, "SIGNED-IN") {
			t.Errorf("remedy = %q, want it to send the user to the signed-in account", c.Remedy)
		}
	case stateFail:
		if c.Remedy == "" {
			t.Error("a failure to resolve the hive carries no remedy")
		}
	default:
		t.Fatalf("state = %q", c.State)
	}
	t.Logf("proxy hive on this machine: %s — %s", c.State, c.Detail)
}

// TestPlatformChecksAreBothPresent: collectChecks appends whatever
// platformChecks returns, and a check silently dropped from that list is a
// question `dpb doctor` stops asking. The names are what doctor's report and
// every test that reads it index by.
func TestPlatformChecksAreBothPresent(t *testing.T) {
	got := platformChecks(paths.Layout{})
	names := make([]string, 0, len(got))
	for _, c := range got {
		names = append(names, c.Name)
	}
	joined := strings.Join(names, ",")
	if joined != "wintun driver,proxy hive" {
		t.Fatalf("platformChecks() = [%s], want [wintun driver,proxy hive]", joined)
	}
}

// TestHarnessMachineChecksMatchThePlatformNames is the drift guard for the
// stand-in. The harness answers for these two checks by name, and a rename in
// doctor_windows.go that left the harness behind would give `dpb doctor` FOUR
// platform checks in a test and two in production — with the real ones' states
// leaking back in, which is the dependency on the runner's driver inventory
// this seam exists to remove.
func TestHarnessMachineChecksMatchThePlatformNames(t *testing.T) {
	real := platformChecks(paths.Layout{})
	fake := harnessMachineChecks()(paths.Layout{})
	if len(real) != len(fake) {
		t.Fatalf("the harness answers %d platform check(s), production has %d", len(fake), len(real))
	}
	for i := range real {
		if real[i].Name != fake[i].Name {
			t.Errorf("check %d is %q in production and %q in the harness", i, real[i].Name, fake[i].Name)
		}
		if fake[i].State != stateOK {
			t.Errorf("the harness's %q is %q; the stand-in describes a supported machine",
				fake[i].Name, fake[i].State)
		}
	}
}
