package cliapp

import (
	"strings"
	"testing"
)

// The banner's contract is that it states only what already happened.
//
// Under --dry-run it did not. It printed
//
//	--dry-run: nothing below was applied.
//
//	system settings applied and verified:
//	  - configure en0 10.255.90.1 -> 10.255.90.2 mtu 1500 up
//	  ...
//
//	Ctrl-C reverts every change above.
//
// — a header claiming six settings were applied and verified over six that were
// neither, and a closing promise to revert changes that do not exist. The
// disclaimer above it means nobody is endangered, and that is exactly why this
// is worth fixing rather than shrugging at: this is the same defect class as a
// prober narrating a conclusion its own numbers contradict, and the header is
// the line that gets quoted, screenshotted and pasted into a bug report.

// TestDryRunBannerStatesAPlanNotAResult drives the shipped command, so it
// asserts the text a user actually sees.
func TestDryRunBannerStatesAPlanNotAResult(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "both", "--dry-run")
	out := h.out.String()

	// There has to be a list, or this test would pass on a banner that printed
	// nothing at all.
	if !strings.Contains(out, "\n    - ") {
		t.Fatalf("--dry-run listed no system settings, so there is nothing to make a claim about:\n%s", out)
	}
	if strings.Contains(out, "applied and verified") {
		t.Errorf("the --dry-run banner claims settings were applied and verified; not one of "+
			"them was applied, and nothing was verified:\n%s", out)
	}
	if !strings.Contains(out, "WOULD be applied") {
		t.Errorf("the --dry-run banner does not say the list is a plan:\n%s", out)
	}
	if strings.Contains(out, "Ctrl-C reverts every change above") {
		t.Errorf("the --dry-run banner promises to revert changes that were never made:\n%s", out)
	}
	if !strings.Contains(out, "nothing to") {
		t.Errorf("the --dry-run banner does not say there is nothing to revert:\n%s", out)
	}
	// The disclaimer stays. It is not the fix — it was already there while the
	// header contradicted it — but removing it would be a regression.
	if !strings.Contains(out, "--dry-run: nothing below was applied.") {
		t.Errorf("the --dry-run disclaimer is gone:\n%s", out)
	}
}

// TestAppliedBannerStillClaimsWhatItVerified is the other half, and the reason
// the fix is a branch rather than a deletion: on a real run those settings WERE
// applied and independently verified, and saying so is the whole point of a
// banner that reports facts.
func TestAppliedBannerStillClaimsWhatItVerified(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "both")
	out := h.out.String()

	if !strings.Contains(out, "system settings applied and verified:") {
		t.Errorf("a real run does not report what it applied and verified:\n%s", out)
	}
	if strings.Contains(out, "WOULD be applied") {
		t.Errorf("a real run describes its applied settings as a plan:\n%s", out)
	}
	if !strings.Contains(out, "Ctrl-C reverts every change above") {
		t.Errorf("a real run does not promise to revert what it changed:\n%s", out)
	}
}
