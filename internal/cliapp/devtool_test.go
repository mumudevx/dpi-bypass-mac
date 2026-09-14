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

// TestCaptureSysconfRefusesToRunWithoutAnOut pins the replacement for a
// default that used to be internal/testwin/fixtures — i.e. inside whatever
// checkout the developer was standing in. This command reads a machine's live
// network configuration; writing that into a git working tree unless told
// otherwise is how a corporate PAC URL gets committed by someone who only
// meant to look at a routing table. scwindows redacts the contents
// (capture.go's redaction comment), and this pins the other half: there is no
// default destination at all, on any platform, so nothing is ever written
// anywhere the operator did not name.
//
// The failure must also be the REQUIRED-FLAG failure and not the
// platform-refusal one, which is why the message is checked: an unmet
// requirement that happened to look like "windows only" would leave this
// passing on darwin for the wrong reason.
func TestCaptureSysconfRefusesToRunWithoutAnOut(t *testing.T) {
	t.Parallel()
	r := run(t, "devtool", "capture-sysconf")
	if r.code == 0 {
		t.Fatalf("exit code = 0; capture-sysconf must require --out\nstdout: %s", r.stdout)
	}
	if !strings.Contains(r.stderr, `required flag(s) "out" not set`) {
		t.Errorf("stderr = %q, want cobra's unmet-required-flag message for --out", r.stderr)
	}
}

// TestCaptureSysconfHelpStatesWhatItRedacts: the privacy behaviour is only
// trustworthy if the person running the command can see it without reading
// the source. Cobra prints Long for `--help`, so these are the claims that
// must survive any future edit of that text — each one names a thing the
// capture does NOT write out.
func TestCaptureSysconfHelpStatesWhatItRedacts(t *testing.T) {
	t.Parallel()
	r := run(t, "devtool", "capture-sysconf", "--help")
	if r.code != 0 {
		t.Fatalf("exit code = %d\nstderr: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"PRIVACY",
		"auto-config (PAC) URL",
		"documentation address",
		"--out is required",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("capture-sysconf --help must state %q:\n%s", want, r.stdout)
		}
	}
}
