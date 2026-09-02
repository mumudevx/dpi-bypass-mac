package probe_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

func sampleReport(t *testing.T) probe.Report {
	t.Helper()
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	// The full sweep, so the report has an unmeasurable row to render:
	// chunk:size=4 is refused by the emitter at this segment budget.
	o.Depth = probe.DepthFull
	o.Resolvers = []resolve.Resolver{
		cleanResolver{label: "udp-yandex-1253"},
		sinkholeResolver{label: "udp-isp"},
	}
	rep, err := probe.NewRunner(o).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep.ToolVersion = "v0.0.0-test"
	rep.NetworkKey = "wifi:test"
	return rep
}

// TestReportTextSaysWhatWasNotMeasured. A report that prints only conclusions
// is indistinguishable from one that guessed them, and the inspection window is
// the one number this build cannot produce.
func TestReportTextSaysWhatWasNotMeasured(t *testing.T) {
	rep := sampleReport(t)
	var buf bytes.Buffer
	if err := rep.Text(&buf); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"DNS transports",
		"block shape",
		"first-record limit",
		"inspection window  unmeasured",
		"ranked candidates",
		"winner",
		"evidence",
		"SINKHOLE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
	// A candidate the emitter refused must be labelled, never printed as 0/N.
	if !strings.Contains(out, "UNMEASURABLE") {
		t.Errorf("no candidate was labelled unmeasurable, but chunk:size=4 is refused here:\n%s", out)
	}
}

func TestReportJSONIsSelfDescribing(t *testing.T) {
	rep := sampleReport(t)
	var buf bytes.Buffer
	if err := rep.JSON(&buf); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	for _, key := range []string{
		"created_at", "shape", "confidence", "noise_rate", "blocked", "not_blocked",
		"winner", "ladder", "dns", "classification", "ranked", "evidence", "trials",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("the JSON has no %q key", key)
		}
	}
	class, _ := got["classification"].(map[string]any)
	if measured, _ := class["inspect_bytes_measured"].(bool); measured {
		t.Error("the JSON claims the inspection window was measured")
	}
	// Every trial carries whether it counted, so a reader can rebuild the
	// denominators rather than trusting them.
	trials, _ := got["trials"].([]any)
	if len(trials) == 0 {
		t.Fatal("the JSON carries no trials")
	}
	first, _ := trials[0].(map[string]any)
	if _, ok := first["scorable"]; !ok {
		t.Error("a trial does not say whether it was scorable")
	}
}

func TestReportExport(t *testing.T) {
	rep := sampleReport(t)
	line := rep.Export()
	if !strings.HasPrefix(line, "dpb apply 'tlsfrag:pos=snimid'") {
		t.Errorf("export = %q, want a runnable dpb apply line", line)
	}
	empty := probe.Report{}
	if got := empty.Export(); !strings.Contains(got, "no working strategy") {
		t.Errorf("an empty report exported %q", got)
	}
}

func TestReportTextOnAnEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := (probe.Report{}).Text(&buf); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "(none)") || !strings.Contains(out, "winner     none") {
		t.Errorf("an empty report does not read as empty:\n%s", out)
	}
}

// TestReportTextSurfacesAWriteError: a long report must not silently truncate.
func TestReportTextSurfacesAWriteError(t *testing.T) {
	want := errors.New("disk full")
	err := sampleReport(t).Text(failWriter{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("Text error = %v, want %v", err, want)
	}
	if err := (probe.Report{}).JSON(failWriter{err: want}); !errors.Is(err, want) {
		t.Fatalf("JSON error = %v, want %v", err, want)
	}
}

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func TestScoreAccessors(t *testing.T) {
	s := probe.Score{
		Spec: "chunk:size=12", BypassPass: 3, BypassTotal: 6,
		ControlPass: 8, ControlTotal: 8, FragilePass: 14, FragileTotal: 20,
	}
	if s.BypassRate() != 0.5 || s.ControlRate() != 1 || s.FragileRate() != 0.7 {
		t.Errorf("rates = %v %v %v", s.BypassRate(), s.ControlRate(), s.FragileRate())
	}
	if s.Label() != "chunk:size=12" {
		t.Errorf("Label = %q", s.Label())
	}
	if (probe.Score{}).Label() != "plain" {
		t.Errorf("the empty spec must render as plain")
	}
	if (probe.Score{}).BypassRate() != 0 {
		t.Error("a rate over no trials must be 0, not NaN")
	}
}

// TestWriteConfigRefusesWithNothingMeasured: a file that says "this network was
// measured" when it was not is worse than no file.
func TestWriteConfigRefusesWithNothingMeasured(t *testing.T) {
	err := probe.Report{Confidence: probe.ConfidenceLow, Ladder: []string{""}}.
		WriteConfig(t.TempDir() + "/tuned.toml")
	if err == nil {
		t.Fatal("WriteConfig wrote a profile with nothing measured as blocked")
	}
}

// TestTunedCarriesTheRankedEvidence: a user who does not trust the winner must
// be able to read the table rather than re-run the tune.
func TestTunedCarriesTheRankedEvidence(t *testing.T) {
	tuned := sampleReport(t).Tuned()
	if len(tuned.Candidates) < 2 {
		t.Fatalf("the profile carries %d candidates", len(tuned.Candidates))
	}
	if tuned.Candidates[0].Spec != "tlsfrag:pos=snimid" {
		t.Errorf("candidate 1 = %q", tuned.Candidates[0].Spec)
	}
	if len(tuned.Resolvers) == 0 {
		t.Error("the profile carries no resolver order")
	}
	if tuned.Resolvers[0] != "udp-yandex-1253" {
		t.Errorf("resolver order starts %q, want the clean transport", tuned.Resolvers[0])
	}
	if err := tuned.Validate(); err != nil {
		t.Errorf("the rendered profile does not validate: %v", err)
	}
}

func TestDNSOutcomeNames(t *testing.T) {
	for out, want := range map[probe.DNSOutcome]string{
		probe.DNSUntried:     "-",
		probe.DNSOK:          "ok",
		probe.DNSTimeout:     "timeout",
		probe.DNSSinkhole:    "SINKHOLE",
		probe.DNSRcode:       "rcode",
		probe.DNSEmpty:       "empty",
		probe.DNSError:       "error",
		probe.DNSOutcome(99): "invalid",
	} {
		if got := out.String(); got != want {
			t.Errorf("DNSOutcome(%d) = %q, want %q", out, got, want)
		}
	}
	for shape, want := range map[probe.Shape]string{
		probe.ShapeUnknown: "unknown",
		probe.ShapeClean:   "clean",
		probe.ShapeIPBlock: "ip-block",
		probe.Shape(99):    "invalid",
	} {
		if got := shape.String(); got != want {
			t.Errorf("Shape(%d) = %q, want %q", shape, got, want)
		}
	}
}

// TestClassifyRecordsAnUnavailableProbeAsUnmeasurable: an op this build does not
// register produces no measurement, and the evidence must say so rather than
// reading as a failed probe.
func TestClassifyRecordsAnUnavailableProbeAsUnmeasurable(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Depth = probe.DepthQuick
	o.Registry = registryWithout(t, "split")

	rep, err := probe.NewRunner(o).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found bool
	for _, e := range rep.Class.Evidence {
		if e.Method == "split:pos=snimid" && strings.Contains(e.Observed, "unmeasurable") {
			found = true
		}
	}
	if !found {
		t.Errorf("the split axis was not recorded as unmeasurable:\n%+v", rep.Class.Evidence)
	}
	if rep.Class.TCPSplit {
		t.Error("an unmeasurable axis was reported as working")
	}
}

func registryWithout(t *testing.T, name string) *strategy.Registry {
	t.Helper()
	r := strategy.NewRegistry()
	for _, op := range opsExcept(name) {
		r.Register(op)
	}
	return r
}

func TestRunnerWarningsAreCopied(t *testing.T) {
	r := probe.NewRunner(probe.Options{})
	if got := r.Warnings(); len(got) != 0 {
		t.Errorf("a fresh runner has warnings: %v", got)
	}
	if _, err := r.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight with no resolvers = %v, want nil", err)
	}
	w := r.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], "no resolver chain") {
		t.Errorf("warnings = %v, want the unmeasured-DNS notice", w)
	}
	w[0] = "mutated"
	if r.Warnings()[0] == "mutated" {
		t.Error("Warnings returns the runner's own slice")
	}
}

func TestRunnerHonoursACancelledContext(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Depth = probe.DepthQuick
	o.Timeout = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := probe.NewRunner(o).Run(ctx)
	if err == nil {
		t.Fatal("Run on a cancelled context returned no error")
	}
}

// TestBaselinePinsAnUnpinnedTargetThroughOurOwnChain: a target given as a bare
// name must be resolved through dpb's chain and pinned, never left to a
// hostname dial. MEASUREMENTS.md §5.4 records a whole compatibility matrix
// invalidated because Go's resolver answered blocked names with the ISP
// sinkhole and every emitter was scored against a blackhole.
func TestBaselinePinsAnUnpinnedTargetThroughOurOwnChain(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Depth = probe.DepthQuick
	o.Chain = resolve.NewChain(resolve.Options{
		Resolvers: []resolve.Resolver{loopbackResolver{label: "udp-fixture"}},
		Logf:      t.Logf,
	})
	// discord.com carries a port but no address, so the baseline has to resolve
	// and pin it before §1's benign-SNI experiment is even possible.
	o.Targets = []probe.Target{
		{Host: "discord.com", Port: lab.port(), Kind: probe.TargetBlocked},
		{Host: labControl, Port: lab.port(), Kind: probe.TargetControl, Addr: lab.addr()},
	}

	r := probe.NewRunner(o)
	blocked, _, err := r.Baseline(context.Background())
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if len(blocked) != 1 {
		t.Fatalf("blocked = %v, want discord.com", blocked)
	}
	if blocked[0].Addr != "127.0.0.1" {
		t.Errorf("the target was not pinned: Addr = %q", blocked[0].Addr)
	}
}

// TestRankBreaksATieOnLatency: two candidates identical on every other key are
// separated by median latency, to the millisecond. Sub-millisecond differences
// are noise, and letting noise decide key 6 would make key 7 — the run-to-run
// stability key — unreachable.
func TestRankBreaksATieOnLatency(t *testing.T) {
	blocked := blockedTargets("discord.com")
	slow := trials("tlsevery:period=16", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)
	fast := trials("tlsevery:period=64", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)
	for i := range slow {
		slow[i].Latency = 90 * time.Millisecond
		fast[i].Latency = 20 * time.Millisecond
	}
	got := probe.Rank(append(slow, fast...), blocked, docs())
	if got[0].Spec != "tlsevery:period=64" {
		t.Errorf("rank 1 = %q, want the faster of two otherwise identical candidates (%s)",
			got[0].Spec, specList(got))
	}

	// A candidate that never passed has no latency sample, and no sample must
	// not win a latency tie-break against one that has.
	none := trials("tlsevery:period=128", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)
	for i := range none {
		none[i].Latency = 0
	}
	got = probe.Rank(append(none, slow...), blocked, docs())
	if got[0].Spec != "tlsevery:period=16" {
		t.Errorf("rank 1 = %q, want the candidate with a measured latency (%s)",
			got[0].Spec, specList(got))
	}
}

// TestProgressIsCalledSerially. Trials run concurrently, so an OnProgress
// callback that keeps a "last printed at" variable and writes to one stream —
// which is what every progress renderer looks like — is a data race unless the
// Runner serialises the calls. The unguarded counter and slice below are the
// assertion: under -race they fail the moment two trials report at once.
func TestProgressIsCalledSerially(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Depth = probe.DepthQuick

	var calls int
	var phases []string
	o.OnProgress = func(p probe.Progress) {
		calls++
		phases = append(phases, p.Phase)
	}

	if _, err := probe.NewRunner(o).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls == 0 || len(phases) != calls {
		t.Fatalf("OnProgress was called %d times and recorded %d phases", calls, len(phases))
	}
}

// TestCapsLabelDoesNotSayNone: the CLI passes a zero Cap, meaning "ask the
// transport", which is what the product does. Rendering that through
// Cap.String would write "none" into the profile, and a reader would take it to
// mean the transport could do nothing at all.
func TestCapsLabelDoesNotSayNone(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Depth = probe.DepthQuick
	o.Caps = 0

	rep, err := probe.NewRunner(o).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Caps == "none" || rep.Caps == "" {
		t.Errorf("Caps = %q for an unset capability set; want something a reader cannot "+
			"mistake for 'the transport can do nothing'", rep.Caps)
	}

	o.Caps = strategy.CapStreamWrite | strategy.CapNoDelay
	rep, err = probe.NewRunner(o).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(rep.Caps, "stream") {
		t.Errorf("Caps = %q, want the explicit set named", rep.Caps)
	}
}
