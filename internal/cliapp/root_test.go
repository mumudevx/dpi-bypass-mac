package cliapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/buildinfo"
)

// The exit codes are a contract: scripts and the LaunchAgent branch on them, so
// they are pinned here rather than left to whatever the constants happen to be.
func TestExitCodesArePinned(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"ok", ExitOK, 0},
		{"error", ExitError, 1},
		{"usage", ExitUsage, 2},
		{"doctor", ExitDoctor, 3},
		{"need root", ExitNeedRoot, 4},
		{"refused", ExitRefused, 5},
	} {
		if tc.got != tc.want {
			t.Errorf("Exit%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// `dpb` with nothing after it has not been asked to do anything. Exiting 0
// would make it look like it had.
func TestNoArgsIsUsage(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), Env{Stdout: &out, Stderr: &errOut})
	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "probe") {
		t.Errorf("help must go to stderr and list the commands, got %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("nothing may go to stdout: %q", out.String())
	}
}

func TestUnknownCommandNamesIt(t *testing.T) {
	t.Parallel()
	r := run(t, "frobnicate")
	if r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
	if !strings.Contains(r.stderr, `"frobnicate"`) {
		t.Errorf("stderr = %q, want it to name the unknown command", r.stderr)
	}
}

func TestUnknownFlagIsUsage(t *testing.T) {
	t.Parallel()
	r := run(t, "probe", "--host", "discord.com", "--nonsense")
	if r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

func TestHelpAndVersion(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"help"}, {"--help"}, {"probe", "--help"}, {"strategy", "--help"}} {
		if r := run(t, args...); r.code != ExitOK {
			t.Errorf("dpb %s: exit code = %d, want 0", strings.Join(args, " "), r.code)
		}
	}

	// `dpb version` and `dpb --version` must agree, and must print exactly the
	// one-line identity: a release script parses it.
	want := buildinfo.Short()
	for _, args := range [][]string{{"version"}, {"--version"}} {
		r := run(t, args...)
		if r.code != ExitOK {
			t.Errorf("dpb %s: exit code = %d", strings.Join(args, " "), r.code)
		}
		if strings.TrimSpace(r.stdout) != want {
			t.Errorf("dpb %s: stdout = %q, want %q", strings.Join(args, " "), r.stdout, want)
		}
	}
}

func TestVersionJSON(t *testing.T) {
	t.Parallel()
	r := run(t, "version", "--json")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d", r.code)
	}
	var got struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Platform  string `json:"platform"`
		UserAgent string `json:"user_agent"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.stdout)
	}
	if got.Name != buildinfo.Name || got.Version != buildinfo.V() {
		t.Errorf("name/version = %q/%q, want %q/%q", got.Name, got.Version, buildinfo.Name, buildinfo.V())
	}
	if got.Platform != buildinfo.Platform() {
		t.Errorf("platform = %q, want %q", got.Platform, buildinfo.Platform())
	}
	// The user agent must not leak a per-build-unique string: a DoH resolver on
	// a censored line is a party we do not have to trust.
	if strings.Contains(got.UserAgent, buildinfo.C()) && buildinfo.C() != "unknown" {
		t.Errorf("user agent %q carries the commit", got.UserAgent)
	}
}

func TestExecuteWritesToTheGivenStreamsOnly(t *testing.T) {
	t.Parallel()
	// Nil streams must not panic: cmd/dpb is entitled to pass whatever it has.
	if code := Execute(context.Background(), Env{Args: []string{"version"}}); code != ExitOK {
		t.Errorf("exit code = %d with nil streams", code)
	}
}

func TestUsageAndRefusedErrorsCarryTheirCode(t *testing.T) {
	t.Parallel()
	ue := usagef("bad thing %d", 7)
	if !strings.Contains(ue.Error(), "bad thing 7") {
		t.Errorf("usagef lost its message: %v", ue)
	}
	var asUsage usageError
	if !errors.As(ue, &asUsage) {
		t.Error("usagef must produce a usageError")
	}

	re := refusedError{err: errors.New("vpn owns the default route")}
	var asRefused refusedError
	if !errors.As(error(re), &asRefused) {
		t.Error("refusedError must be matchable")
	}
	if !strings.Contains(re.Error(), "vpn") {
		t.Errorf("refusedError lost its message: %v", re)
	}
	if re.Unwrap() == nil || asUsage.Unwrap() == nil {
		t.Error("both wrappers must unwrap")
	}
}

func TestCobraUsageErrorDetection(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		`unknown command "x" for "dpb"`,
		"unknown flag: --nope",
		"unknown shorthand flag: 'q' in -q",
		"flag needs an argument: --host",
		`invalid argument "x" for "--reps"`,
		"accepts 1 arg(s), received 0",
		"requires at least 1 arg(s)",
	} {
		if !isCobraUsageError(errors.New(s)) {
			t.Errorf("%q must be recognised as a usage error", s)
		}
	}
	if isCobraUsageError(errors.New("connection reset by peer")) {
		t.Error("a runtime failure must not be classed as usage")
	}
}

// A cancelled context must not turn into a usage error: the user typed nothing
// wrong, the run was interrupted.
func TestCancelledContextIsAnError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	code := Execute(ctx, Env{
		Args:   []string{"probe", "--host", "discord.com", "--addr", "127.0.0.1", "--port", "1", "--reps", "2"},
		Stdout: &out, Stderr: &errOut,
	})
	if code == ExitUsage {
		t.Errorf("exit code = %d, want anything but usage", code)
	}
}

func TestVerbosityFlags(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"-v", "version"},
		{"-vv", "version"},
		{"--log-json", "version"},
	} {
		if r := run(t, args...); r.code != ExitOK {
			t.Errorf("dpb %s: exit code = %d", strings.Join(args, " "), r.code)
		}
	}
}
