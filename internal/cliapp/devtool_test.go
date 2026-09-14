package cliapp

import (
	"strings"
	"testing"
)

// TestDevtoolIsHiddenFromHelp: `dpb devtool` exists so capture-sysconf is a
// real subcommand rather than a script nobody remembers, but it is not
// something a user ever needs to type — see devtool.go's doc comment. Cobra's
// Hidden field removes a command from its parent's listing and from the
// generated usage text; this pins that it actually took effect rather than
// silently doing nothing, the same failure mode the platform stub for
// runCaptureSysconf is written to avoid on the other side of this feature.
func TestDevtoolIsHiddenFromHelp(t *testing.T) {
	t.Parallel()
	r := run(t, "--help")
	if r.code != 0 {
		t.Fatalf("dpb --help: exit code = %d", r.code)
	}
	// Only the top-level command list is checked for "devtool": a root
	// --help never lists a second level down regardless of hidden status, so
	// "capture-sysconf" not appearing here would prove nothing about Hidden
	// actually working.
	if strings.Contains(r.stdout, "devtool") {
		t.Errorf("dpb --help must not list devtool:\n%s", r.stdout)
	}

	// Hidden means "not surfaced in the top-level listing", not "unreachable
	// when addressed directly" — a developer who already knows the command
	// exists must still be able to ask it for help.
	sub := run(t, "devtool", "--help")
	if sub.code != 0 {
		t.Fatalf("dpb devtool --help: exit code = %d\n%s", sub.code, sub.stderr)
	}
	if !strings.Contains(sub.stdout, "capture-sysconf") {
		t.Errorf("dpb devtool --help must list capture-sysconf:\n%s", sub.stdout)
	}
}

// TestDevtoolCaptureSysconfIsReachable pins that the command is actually
// wired into the tree, as opposed to merely defined: a typo in AddCommand or
// in the Use string would make this "unknown command", not a platform
// refusal, and the two must not be confused with each other. --out is always
// pointed at a temp directory here so this test never writes into the repo's
// own internal/testwin/fixtures, on either platform: on Windows this
// actually runs capture-sysconf for real.
func TestDevtoolCaptureSysconfIsReachable(t *testing.T) {
	t.Parallel()
	r := run(t, "devtool", "capture-sysconf", "--out", t.TempDir())
	if strings.Contains(r.stderr, "unknown command") {
		t.Fatalf("`dpb devtool capture-sysconf` is not registered: %s", r.stderr)
	}
}
