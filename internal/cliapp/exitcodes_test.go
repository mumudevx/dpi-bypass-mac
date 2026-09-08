package cliapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/testcensor"
)

// The exit codes are a scripting contract. Two commands that return the same
// number for two unrelated conditions make a shell script that branches on
// `$?` wrong, and there is no second signal to disambiguate them: the message
// goes to stderr in prose.
//
// This test exists because `dpb tune` and `dpb service install --system` both
// returned 4 in one shipped binary — "nothing is blocked here" and "needs
// root" — which a caller cannot tell apart.
func TestExitCodesAreDistinct(t *testing.T) {
	codes := map[string]int{
		"ExitOK":             ExitOK,
		"ExitError":          ExitError,
		"ExitUsage":          ExitUsage,
		"ExitDoctor":         ExitDoctor,
		"ExitNeedRoot":       ExitNeedRoot,
		"ExitRefused":        ExitRefused,
		"ExitNothingBlocked": ExitNothingBlocked,
	}
	seen := make(map[int]string, len(codes))
	for name, code := range codes {
		if other, dup := seen[code]; dup {
			t.Errorf("%s and %s are both exit code %d; a script cannot branch on that",
				other, name, code)
			continue
		}
		seen[code] = name
	}
}

// The two conditions that actually collided, driven through the real commands
// in one process, because a constants test alone would not catch a command that
// returns a literal.
func TestNothingBlockedAndNeedRootReturnDifferentCodes(t *testing.T) {
	lab := newCensorLab(t, testcensor.Open(0))
	out := filepath.Join(t.TempDir(), "tuned.toml")
	tuneRes := run(t, tuneArgs(lab, out, "--timeout", "500ms")...)

	c := newCLI(t)
	// --system on an unelevated layout is the "needs root" path.
	rootRes := c.exec(t, "service", "install", "--system")

	if tuneRes.code == rootRes.code {
		t.Fatalf("`dpb tune` with nothing blocked and `dpb service install --system` "+
			"both exit %d; a script cannot tell them apart\ntune: %s\nservice: %s",
			tuneRes.code, tuneRes.stderr, rootRes.stderr)
	}
	if rootRes.code != ExitNeedRoot {
		t.Errorf("service install --system exited %d, want ExitNeedRoot %d: %s",
			rootRes.code, ExitNeedRoot, rootRes.stderr)
	}
	if tuneRes.code != ExitNothingBlocked {
		t.Errorf("tune with nothing blocked exited %d, want ExitNothingBlocked %d: %s",
			tuneRes.code, ExitNothingBlocked, tuneRes.stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a profile was written with nothing measured as blocked")
	}
}

// A code a script has to branch on has to be documented where the user looks
// for it, which is `--help`, not the source.
func TestHelpDocumentsTheExitCodesTheCommandReturns(t *testing.T) {
	c := newCLI(t)

	tune := c.exec(t, "tune", "--help")
	if !strings.Contains(tune.stdout, "exit "+itoa(ExitNothingBlocked)) {
		t.Errorf("`dpb tune --help` does not name exit code %d:\n%s",
			ExitNothingBlocked, tune.stdout)
	}

	svc := c.exec(t, "service", "install", "--help")
	if !strings.Contains(svc.stdout, "exit "+itoa(ExitNeedRoot)) {
		t.Errorf("`dpb service install --help` does not name exit code %d:\n%s",
			ExitNeedRoot, svc.stdout)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
