package cliapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

func applyArgs(l *censorLab, out, spec string, extra ...string) []string {
	args := []string{"apply", spec,
		"--target", at("discord.com", l),
		"--control", at("cloudflare.com", l),
		"--fragile", "",
		"--reps", "2",
		"--cooldown", "1ms",
		"--ca-file", l.caPath,
		"--out", out,
	}
	return append(args, extra...)
}

// TestApplyVerifiesBeforeWriting is the point of the command: a strategy
// someone else posted is MEASURED here before it is believed. MEASUREMENTS.md
// §3.5 — "strategy parameters are not portable between implementations".
func TestApplyVerifiesBeforeWriting(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, applyArgs(lab, out, "tlsfrag:pos=snimid")...)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "VERIFIED here") {
		t.Errorf("the command did not say it verified the strategy:\n%s", r.stdout)
	}
	tuned, err := config.LoadTuned(out)
	if err != nil {
		t.Fatalf("the written profile does not load back: %v", err)
	}
	if tuned.Strategy != "tlsfrag:pos=snimid" {
		t.Errorf("profile strategy = %q", tuned.Strategy)
	}
	if len(tuned.Ladder) != 2 || tuned.Ladder[0] != "" {
		t.Errorf("profile ladder = %q; rung 1 must be plain and rung 2 the imported spec", tuned.Ladder)
	}
}

// TestApplyRefusesAStrategyThatDoesNothingHere: the failure mode the command
// exists to prevent. A spec that works on someone else's line must not be
// written here just because they said so.
func TestApplyRefusesAStrategyThatDoesNothingHere(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	// split is measured 0/5 on this DPI (§3.1: it reassembles TCP), and TT2026
	// reproduces that mechanism.
	r := run(t, applyArgs(lab, out, "split:pos=snimid")...)
	if r.code != ExitError {
		t.Fatalf("exit code = %d, want %d\n%s%s", r.code, ExitError, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "did not bypass anything on this line") {
		t.Errorf("the refusal does not say why:\n%s", r.stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an unverified strategy was written anyway")
	}
}

// TestApplyForceMarksItLow: --force writes, but never with a confidence it did
// not earn.
func TestApplyForceMarksItLow(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, applyArgs(lab, out, "split:pos=snimid", "--force")...)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
	}
	tuned, err := config.LoadTuned(out)
	if err != nil {
		t.Fatalf("LoadTuned: %v", err)
	}
	if tuned.Confidence != config.ConfidenceLow {
		t.Errorf("confidence = %q, want %q for a forced import", tuned.Confidence, config.ConfidenceLow)
	}
	if len(tuned.Warnings) == 0 || !strings.Contains(strings.Join(tuned.Warnings, " "), "--force") {
		t.Errorf("the profile does not record that it was forced: %q", tuned.Warnings)
	}
}

func TestApplyExplainsBeforeMeasuring(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, applyArgs(lab, out, "tlsfrag:pos=snimid", "--write=false")...)
	if !strings.Contains(r.stdout, "MEASUREMENTS.md §3.2") {
		t.Errorf("apply does not show where the strategy's claim comes from:\n%s", r.stdout)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("--write=false wrote a profile anyway")
	}
}

func TestApplyUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"plain is not importable", []string{"apply", "", "--write=false"}},
		{"unknown op", []string{"apply", "nosuchop:pos=1", "--write=false"}},
		// A registered-but-rejected op must produce its cited refusal, not
		// "unknown op": telling someone to fix a typo when the mechanism cannot
		// work sends them in the opposite direction.
		{"rejected op", []string{"apply", "tlspad:to=600", "--write=false"}},
		{"contradictory verification", []string{"apply", "chunk:size=12", "--insecure", "--ca-file", "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.args...)
			if r.code != ExitUsage {
				t.Errorf("exit code = %d, want %d\n%s", r.code, ExitUsage, r.stderr)
			}
		})
	}
}
