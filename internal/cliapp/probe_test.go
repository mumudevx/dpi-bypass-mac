package cliapp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

type result struct {
	code   int
	stdout string
	stderr string
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), Env{Args: args, Stdout: &out, Stderr: &errOut})
	t.Logf("dpb %s -> %d\n%s%s", strings.Join(args, " "), code, out.String(), errOut.String())
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

// TestProbeAcceptanceMatrixOffline is the milestone's acceptance criterion run
// off a censored line: the same three commands, against testcensor at
// --addr 127.0.0.1, with the verdicts MEASUREMENTS.md §1 and §3.2 record.
func TestProbeAcceptanceMatrixOffline(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))

	cases := []struct {
		name     string
		host     string
		spec     string
		wantLine string
		wantCode int
	}{
		{"blocked, plain", "discord.com", "", "0/5 PASS   verdict RESET", ExitError},
		{"blocked, tlsfrag", "discord.com", "tlsfrag:pos=snimid", "5/5 PASS   verdict PASS", ExitOK},
		{"benign control, same address", "cloudflare.com", "", "5/5 PASS   verdict PASS", ExitOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, "probe",
				"--host", tc.host,
				"--addr", "127.0.0.1",
				"--port", lab.portArg(),
				"--strategy", tc.spec,
				"--reps", "5",
				"--ca-file", lab.caPath,
			)
			if !strings.Contains(r.stdout, tc.wantLine) {
				t.Fatalf("stdout does not contain %q:\n%s", tc.wantLine, r.stdout)
			}
			if r.code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", r.code, tc.wantCode)
			}
		})
	}
}

// A blocked host with no strategy must point at the emitter that is measured to
// clear it. A measurement instrument that leaves the user holding a label and
// no action has done half its job.
func TestProbeSuggestsTheMeasuredEmitter(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	r := run(t, "probe", "--host", "discord.com", "--addr", "127.0.0.1",
		"--port", lab.portArg(), "--reps", "1", "--ca-file", lab.caPath)

	if !strings.Contains(r.stdout, "tlsfrag:pos=snimid") {
		t.Errorf("a RESET verdict on plain must name the measured emitter:\n%s", r.stdout)
	}
}

func TestProbeJSON(t *testing.T) {
	lab := newCensorLab(t, testcensor.TT2026("discord.com"))
	r := run(t, "probe", "--host", "discord.com", "--addr", "127.0.0.1",
		"--port", lab.portArg(), "--reps", "2", "--json", "--ca-file", lab.caPath)

	var got probeJSON
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.stdout)
	}
	if got.Host != "discord.com" || got.Addr != "127.0.0.1" {
		t.Errorf("host/addr = %q/%q", got.Host, got.Addr)
	}
	if got.Verdict != "RESET" || got.Pass != 0 || got.Total != 2 {
		t.Errorf("verdict=%s pass=%d total=%d, want RESET 0 2", got.Verdict, got.Pass, got.Total)
	}
	if len(got.Trials) != 2 {
		t.Fatalf("trials = %d, want 2", len(got.Trials))
	}
	for i, tr := range got.Trials {
		if tr.Round != i+1 {
			t.Errorf("trial %d round = %d", i, tr.Round)
		}
		if tr.Err == "" {
			t.Errorf("trial %d: a failed trial must carry its error", i)
		}
		if tr.At == "" {
			t.Errorf("trial %d: missing timestamp", i)
		}
	}
}

// --insecure has to be spelled out because it changes what PASS means. Pairing
// it with --ca-file asks for two different trust models at once.
func TestProbeRejectsContradictoryTrustFlags(t *testing.T) {
	r := run(t, "probe", "--host", "discord.com", "--addr", "127.0.0.1",
		"--insecure", "--ca-file", "/nonexistent")
	if r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

func TestProbeUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no host", []string{"probe"}, "--host"},
		{"zero reps", []string{"probe", "--host", "discord.com", "--reps", "0"}, "reps"},
		{"unknown op", []string{"probe", "--host", "discord.com", "--strategy", "nosuchop"}, "unknown op"},
		{"bad address", []string{"probe", "--host", "discord.com", "--addr", "not-an-ip"}, "not an IP"},
		{"positional argument", []string{"probe", "discord.com"}, "unknown command"},
		{"missing ca file", []string{"probe", "--host", "d.example", "--addr", "127.0.0.1", "--ca-file", "/no/such/file"}, "ca-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.args...)
			if r.code == ExitOK {
				t.Fatalf("exit code = 0, want a failure")
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Errorf("stderr = %q, want it to mention %q", r.stderr, tc.want)
			}
		})
	}
}

// An unknown op is a typo, not a runtime failure, and must exit 2 so a script
// can tell "you asked for something that does not exist" from "it did not work".
func TestProbeUnknownOpIsUsage(t *testing.T) {
	r := run(t, "probe", "--host", "discord.com", "--strategy", "nosuchop")
	if r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

// A dial that never connects is DIAL-FAIL, and it must say so rather than
// reporting a strategy result nothing measured.
func TestProbeDialFailure(t *testing.T) {
	// Port 1 on loopback with nothing bound: connection refused, immediately.
	r := run(t, "probe", "--host", "discord.com", "--addr", "127.0.0.1",
		"--port", "1", "--reps", "1", "--timeout", "2s")

	if !strings.Contains(r.stdout, "DIAL-FAIL") {
		t.Errorf("stdout = %q, want DIAL-FAIL", r.stdout)
	}
	if r.code != ExitError {
		t.Errorf("exit code = %d, want %d", r.code, ExitError)
	}
}

// MEASUREMENTS.md §2: the ISP resolver answers every blocked name with
// 195.175.254.2. Pinning it must be reported as reaching a censor, with the
// remediation, and never dialled.
func TestProbeAgainstTheSinkhole(t *testing.T) {
	r := run(t, "probe", "--host", "discord.com", "--addr", "195.175.254.2", "--reps", "1")
	if !strings.Contains(r.stdout, "BLOCKPAGE") {
		t.Fatalf("stdout = %q, want BLOCKPAGE", r.stdout)
	}
	if !strings.Contains(r.stdout, "sinkhole") {
		t.Errorf("the remediation must explain what was reached:\n%s", r.stdout)
	}
}

func TestSummarise(t *testing.T) {
	t.Parallel()
	mk := func(vs ...probe.Verdict) []probe.Trial {
		out := make([]probe.Trial, len(vs))
		for i, v := range vs {
			out[i] = probe.Trial{Round: i + 1, Verdict: v}
		}
		return out
	}
	cases := []struct {
		name string
		in   []probe.Trial
		want probe.Verdict
	}{
		{"empty", nil, probe.VerdictUnknown},
		{"all pass", mk(probe.VerdictPass, probe.VerdictPass), probe.VerdictPass},
		{"all reset", mk(probe.VerdictReset, probe.VerdictReset), probe.VerdictReset},
		{"majority reset", mk(probe.VerdictPass, probe.VerdictReset, probe.VerdictReset), probe.VerdictReset},
		{"one failure among passes", mk(probe.VerdictPass, probe.VerdictTimeout), probe.VerdictTimeout},
		// A tie must not flip between runs, and must not report the gentler of
		// the two: a mixed RESET/TIMEOUT line is still a blocked line.
		{"tie", mk(probe.VerdictReset, probe.VerdictTimeout), probe.VerdictTimeout},
	}
	for _, tc := range cases {
		if got := summarise(tc.in); got != tc.want {
			t.Errorf("%s: summarise() = %s, want %s", tc.name, got, tc.want)
		}
	}
	// Stability: the same input must give the same answer every time, even
	// though the counts live in a map.
	in := mk(probe.VerdictReset, probe.VerdictTimeout, probe.VerdictBlockPage)
	first := summarise(in)
	for i := 0; i < 50; i++ {
		if got := summarise(in); got != first {
			t.Fatalf("summarise is not deterministic: %s then %s", first, got)
		}
	}
}

func TestRemedyCoversEveryVerdict(t *testing.T) {
	t.Parallel()
	for _, v := range []probe.Verdict{
		probe.VerdictReset, probe.VerdictTimeout, probe.VerdictBlockPage,
		probe.VerdictHandshakeFail, probe.VerdictDialFail, probe.VerdictLocalError,
	} {
		if remedy(probeResult{Verdict: v}) == "" {
			t.Errorf("%s has no remediation", v)
		}
	}
	if remedy(probeResult{Verdict: probe.VerdictPass}) != "" {
		t.Error("PASS needs no remediation")
	}
	// With a strategy already in play the advice must not be "try the strategy
	// you just tried".
	withSpec := remedy(probeResult{Verdict: probe.VerdictReset, Strategy: "tlsfrag:pos=snimid"})
	if strings.Contains(withSpec, "Try --strategy tlsfrag") {
		t.Errorf("remediation repeats the failed strategy: %q", withSpec)
	}
}

func TestSleepCtxHonoursCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Fatal("sleepCtx must return on a cancelled context")
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("sleepCtx: %v", err)
	}
}

// The chain built for an unpinned probe is the shipped one: DoH first, plain
// UDP on :53 deliberately absent because MEASUREMENTS.md §2 measures it as
// per-QNAME dropped for exactly the names this tool exists to reach.
func TestProbeChainIsTheShippedChain(t *testing.T) {
	t.Parallel()
	g := &globals{env: Env{Stdout: io.Discard, Stderr: io.Discard}}
	c, err := probeChain(g)
	if err != nil {
		t.Fatalf("probeChain: %v", err)
	}
	labels := c.Labels()
	if len(labels) == 0 {
		t.Fatal("the chain has no resolvers")
	}
	if !strings.HasPrefix(labels[0], "doh") {
		t.Errorf("first resolver = %q, want a DoH rung", labels[0])
	}
	for _, l := range labels {
		if strings.Contains(l, ":53") {
			t.Errorf("plain UDP/53 must not be in the chain: %q", l)
		}
	}
}

// --insecure changes what PASS means, so what it produces is asserted rather
// than assumed.
func TestInsecureConfig(t *testing.T) {
	t.Parallel()
	c := insecureConfig("discord.com")
	if !c.InsecureSkipVerify {
		t.Error("--insecure must skip verification")
	}
	if c.ServerName != "discord.com" {
		t.Errorf("ServerName = %q", c.ServerName)
	}
	if c.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", c.MinVersion)
	}
}
