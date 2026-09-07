package cliapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/probe"
	"github.com/mumudevx/dpb/internal/testcensor"
)

// at pins a hostname to the lab's loopback listener, which is the form
// `dpb tune` takes on the command line.
func at(host string, l *censorLab) string {
	return host + "@127.0.0.1:" + l.portArg()
}

// tuneArgs is the shape every test here uses: a pinned blocked target, a pinned
// control, no fragile axis (the lab has one model), and a temp file to write to.
//
// --out is NOT optional in a test. Without it `dpb tune` would write the
// invoking user's real profile, which is a machine change a test must never make.
func tuneArgs(l *censorLab, out string, extra ...string) []string {
	args := []string{"tune",
		at("discord.com", l),
		"--control", at("cloudflare.com", l),
		"--fragile", "",
		"--depth", "quick",
		"--cooldown", "1ms",
		"--ca-file", l.caPath,
		"--out", out,
	}
	return append(args, extra...)
}

// TestTuneWritesAProfileOffline is M13's acceptance clause driven through the
// shipped command: against the measured Türk Telekom mechanism, `dpb tune`
// converges on tlsfrag:pos=snimid and ends by writing a file rather than by
// printing a paragraph of caveats.
func TestTuneWritesAProfileOffline(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, tuneArgs(lab, out)...)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "winner     tlsfrag:pos=snimid") {
		t.Errorf("the report does not name tlsfrag:pos=snimid as the winner:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "wrote "+out) {
		t.Errorf("the command did not say what it wrote:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "delete that file") {
		t.Errorf("the command does not tell the user how to undo it:\n%s", r.stdout)
	}

	tuned, err := config.LoadTuned(out)
	if err != nil {
		t.Fatalf("the written profile does not load back: %v", err)
	}
	if tuned.Strategy != "tlsfrag:pos=snimid" {
		t.Errorf("profile strategy = %q, want tlsfrag:pos=snimid", tuned.Strategy)
	}
	if len(tuned.Ladder) == 0 || tuned.Ladder[0] != "" {
		t.Errorf("profile ladder = %q; rung 1 must be plain", tuned.Ladder)
	}
	if tuned.Classification.FirstRecordLimit == 0 ||
		tuned.Classification.FirstRecordLimit != tuned.Classification.SNIEnd-1 {
		t.Errorf("first-record limit %d with sniEnd %d, want sniEnd-1",
			tuned.Classification.FirstRecordLimit, tuned.Classification.SNIEnd)
	}
}

func TestTuneJSONIsParseable(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, tuneArgs(lab, out, "--json")...)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0\n%s", r.code, r.stderr)
	}
	var got struct {
		Shape      string `json:"shape"`
		Winner     string `json:"winner"`
		Confidence string `json:"confidence"`
		Class      struct {
			FirstRecordLimit int  `json:"first_record_limit"`
			SNIEnd           int  `json:"sni_end"`
			InspectMeasured  bool `json:"inspect_bytes_measured"`
		} `json:"classification"`
		Ranked []struct {
			Spec         string `json:"spec"`
			Unmeasurable bool   `json:"unmeasurable"`
		} `json:"ranked"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, r.stdout)
	}
	if got.Winner != "tlsfrag:pos=snimid" {
		t.Errorf("winner = %q, want tlsfrag:pos=snimid", got.Winner)
	}
	if got.Class.FirstRecordLimit != got.Class.SNIEnd-1 {
		t.Errorf("first_record_limit %d, sni_end %d", got.Class.FirstRecordLimit, got.Class.SNIEnd)
	}
	// The inspection window has no number in this build, and a consumer must be
	// able to tell "zero" from "not measured".
	if got.Class.InspectMeasured {
		t.Error("the report claims the inspection window was measured; it cannot be, see PLAN A2")
	}
	if len(got.Ranked) == 0 {
		t.Error("the JSON carries no ranking")
	}
}

// TestTuneExitsNothingBlockedWhenNothingIsBlocked: the plan's clause, driven
// through the command. Nothing must be written, and no winner invented.
//
// The code is 6, not the 4 the plan's M13 clause originally named: 4 already
// means "needs root" in the same surface's exit-code table, and one binary
// returning it for both left a script unable to tell "re-run with sudo" from
// "there is nothing to measure". See ExitNothingBlocked in root.go.
func TestTuneExitsNothingBlockedWhenNothingIsBlocked(t *testing.T) {
	lab := newCensorLab(t, testcensor.Open(0))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, tuneArgs(lab, out, "--timeout", "500ms")...)
	if r.code != ExitNothingBlocked {
		t.Fatalf("exit code = %d, want %d\n%s%s", r.code, ExitNothingBlocked, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "nothing in the target set is blocked") {
		t.Errorf("the reason is not stated:\n%s", r.stderr)
	}
	if !strings.Contains(r.stdout, "winner     none") {
		t.Errorf("a winner was reported anyway:\n%s", r.stdout)
	}
	if _, err := os.Stat(out); err == nil {
		t.Errorf("a profile was written with nothing measured as blocked")
	}
}

// TestTuneRefusesAnIPBlock: exit 5, the code the CLI surface reserves for
// "refused for safety: IP-level block".
func TestTuneRefusesAnIPBlock(t *testing.T) {
	lab := newCensorLab(t, testcensor.IPBlock(loopbackPrefix()))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, tuneArgs(lab, out)...)
	if r.code != ExitRefused {
		t.Fatalf("exit code = %d, want %d\n%s%s", r.code, ExitRefused, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "no packet strategy can help") {
		t.Errorf("the refusal does not say why:\n%s", r.stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a profile was written against an address-level block")
	}
}

func TestTuneNoWriteWritesNothing(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, tuneArgs(lab, out, "--write=false")...)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0\n%s", r.code, r.stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("--write=false wrote a profile anyway")
	}
}

func TestTuneExport(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	out := filepath.Join(t.TempDir(), "tuned.toml")

	r := run(t, tuneArgs(lab, out, "--export", "--write=false")...)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0\n%s", r.code, r.stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(r.stdout), "dpb apply 'tlsfrag:pos=snimid'") {
		t.Errorf("the export line is not a runnable command:\n%s", r.stdout)
	}
}

func TestTuneUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"bad depth", []string{"tune", "--depth", "thorough", "--write=false"}},
		{"contradictory verification", []string{"tune", "--insecure", "--ca-file", "x.pem", "--write=false"}},
		{"bad pin", []string{"tune", "discord.com@not-an-ip", "--write=false"}},
		{"bad port", []string{"tune", "discord.com:99999", "--write=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := run(t, tc.args...); r.code != ExitUsage {
				t.Errorf("exit code = %d, want %d\n%s", r.code, ExitUsage, r.stderr)
			}
		})
	}
}

func TestParseTargetSpec(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantHost string
		wantPort int
		wantAddr string
	}{
		{"discord.com", "discord.com", 0, ""},
		{"discord.com:8443", "discord.com", 8443, ""},
		{"discord.com@162.159.128.233", "discord.com", 0, "162.159.128.233"},
		{"discord.com@127.0.0.1:1443", "discord.com", 1443, "127.0.0.1"},
		{"discord.com:443@162.159.128.233", "discord.com", 443, "162.159.128.233"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseTargetSpec(tc.in, probe.TargetBlocked)
			if err != nil {
				t.Fatalf("parseTargetSpec(%q): %v", tc.in, err)
			}
			if got.Host != tc.wantHost || got.Port != tc.wantPort || got.Addr != tc.wantAddr {
				t.Errorf("= {%q %d %q}, want {%q %d %q}",
					got.Host, got.Port, got.Addr, tc.wantHost, tc.wantPort, tc.wantAddr)
			}
		})
	}
	for _, bad := range []string{"", "  ", "discord.com@nope", "discord.com@127.0.0.1:0", "@1.2.3.4"} {
		if _, err := parseTargetSpec(bad, probe.TargetBlocked); err == nil {
			t.Errorf("parseTargetSpec(%q) accepted an unusable target", bad)
		}
	}
}

// TestDNSOnlyReportsAnUnmeasuredMatrixAsUnmeasured: `dpb tune --dns-only` is
// the first thing MEASUREMENTS.md §2 says to run, because no packet strategy
// fixes a poisoned resolver. With no resolver chain there is nothing to
// measure, and the command must say so — in the matrix and in a warning —
// rather than printing an empty table that reads as a clean network.
func TestDNSOnlyReportsAnUnmeasuredMatrixAsUnmeasured(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	g := &globals{env: Env{Stdout: &out, Stderr: &errOut}}

	err := runDNSOnly(context.Background(), g, probe.NewRunner(probe.Options{}))
	if err != nil {
		t.Fatalf("runDNSOnly = %v, want nil: an unmeasured matrix is not a failure", err)
	}
	if !strings.Contains(out.String(), "no DNS transports were measured") {
		t.Errorf("the matrix does not say it measured nothing:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "no resolver chain") {
		t.Errorf("the warning was not printed:\n%s", errOut.String())
	}
}
