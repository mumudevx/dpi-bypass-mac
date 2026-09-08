package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/resolve"
	"github.com/mumudevx/dpb/internal/strategy"
)

// Report is a whole tune session.
type Report struct {
	CreatedAt   time.Time
	ToolVersion string
	NetworkKey  string
	Caps        string
	DNS         []resolve.Health
	Matrix      DNSMatrix
	Class       Classification
	Blocked     []string
	NotBlocked  []string
	Ranked      []Score
	Ladder      []string
	Confidence  string
	NoiseRate   float64
	Elapsed     time.Duration
	Warnings    []string
	Trials      []Trial
}

// Winner is the top-ranked candidate that actually bypassed something, or false
// when there is none.
//
// "Top-ranked" alone is not enough: with nothing blocked, plain ranks first and
// is not a bypass strategy. A caller that wrote plain into tuned.toml as a
// winner would be claiming a measurement it did not make.
func (r Report) Winner() (Score, bool) {
	for _, s := range r.Ranked {
		if s.Spec == "" || !s.measured() {
			continue
		}
		if s.BypassPass > 0 {
			return s, true
		}
	}
	return Score{}, false
}

// LadderFrom builds the escalation ladder from the ranking: plain first,
// always, then the best candidate from each distinct MECHANISM.
//
// Rung 1 is plain unconditionally. MEASUREMENTS.md §5.1 measures every
// bypassing emitter breaking Turkish banking, so the first rung is a
// correctness requirement and not a preference the data may overturn.
//
// After that, one rung per op set. Taking the top N of the ranking outright is
// what a first cut does and it is wrong: measured live on Türk Telekom, the top
// four bypassing candidates were tlsfrag at snimid, sniend-1, snistart+1 and
// snistart-1, so the ladder was four cut positions of ONE emitter. A ladder is
// an escalation, and escalating from a reframer to the same reframer at a
// different offset buys nothing — an origin that rejects a handshake spanning
// two records (§5, ten of forty-one Turkish hosts) rejects every one of them
// identically. §5.3 says so directly of rung 3: "chunk-12 — different
// mechanism, 8/8 controls, useful when record splitting is rejected by the
// origin."
func LadderFrom(ranked []Score, max int) []string {
	out := []string{""}
	seen := map[string]bool{}
	for _, s := range ranked {
		if len(out) >= max {
			break
		}
		if s.Spec == "" || !s.measured() || s.BypassPass == 0 {
			continue
		}
		fam := specFamily(s.Spec)
		if seen[fam] {
			continue
		}
		seen[fam] = true
		out = append(out, s.Spec)
	}
	return out
}

// specFamily is the set of op names in a spec, sorted, which is what makes two
// parameterisations of the same emitter one mechanism and a composite its own.
func specFamily(spec string) string {
	names := make([]string, 0, 2)
	for _, tok := range strings.Split(spec, "|") {
		name := strings.TrimSpace(tok)
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, "|")
}

// LadderDepth is how many rungs a written profile carries. Four, matching the
// shipped tr ladder: §6 measures a first visit to a blocked host at ~45 ms for
// two rungs, and a ladder deeper than the attempt budget can reach is a ladder
// whose last rungs are decoration.
const LadderDepth = 4

// Run executes the whole tune and returns a Report.
//
// The phases are the plan's, and each one can stop the run with a result rather
// than an excuse:
//
//	preflight → no clean DNS transport anywhere: report and stop, because no
//	            packet strategy fixes a poisoned resolver.
//	baseline  → every target unreachable even with a benign SNI: ShapeIPBlock,
//	            report and stop, because no desync can help.
//	          → nothing blocked: report and stop WITHOUT a winner, because
//	            inventing one is how a prober lies.
//	classify  → narrow the search order.
//	evaluate  → the sweep, on both axes.
//	rank      → the seven keys.
//
// The Report is returned in every case, including alongside an error, because a
// run that stopped early still measured something and the user is owed it.
func (r *Runner) Run(ctx context.Context) (Report, error) {
	r.started = r.now()
	rep := Report{CreatedAt: r.started, Caps: capsLabel(r.o.Caps)}

	health, err := r.Preflight(ctx)
	rep.DNS, rep.Matrix = health, r.Matrix()
	if err != nil {
		rep.Warnings = r.Warnings()
		rep.Confidence = ConfidenceLow
		rep.Elapsed = r.now().Sub(r.started)
		return rep, err
	}
	r.progress("preflight")

	blocked, notBlocked, err := r.Baseline(ctx)
	rep.Blocked, rep.NotBlocked = hosts(blocked), hosts(notBlocked)
	if err != nil {
		rep.Class = Classification{Shape: r.shape, DNS: health, RSTLatency: r.rstLatency}
		rep.Warnings = r.Warnings()
		rep.Confidence = ConfidenceLow
		rep.Elapsed = r.now().Sub(r.started)
		return rep, err
	}
	r.progress("baseline")

	class, err := r.Classify(ctx)
	rep.Class = class
	if err != nil {
		rep.Warnings = r.Warnings()
		rep.Confidence = ConfidenceLow
		rep.Elapsed = r.now().Sub(r.started)
		return rep, err
	}
	r.progress("classify")

	if len(blocked) == 0 {
		rep.Warnings = r.Warnings()
		rep.Confidence = ConfidenceLow
		rep.NoiseRate = NoiseRate(r.discarded, r.attempted)
		rep.Elapsed = r.now().Sub(r.started)
		return rep, ErrNothingBlocked
	}

	cands := CandidatesWith(r.o.Registry, r.o.Depth, class, r.o.Caps)
	trials, err := r.Evaluate(ctx, cands)
	rep.Trials = trials
	r.progress("rank")

	rep.Ranked = Rank(trials, blocked, r.o.Registry.Docs())
	rep.NoiseRate = NoiseRate(r.discarded, r.attempted)
	rep.Elapsed = r.now().Sub(r.started)
	rep.Warnings = r.Warnings()
	rep.Ladder = LadderFrom(rep.Ranked, LadderDepth)

	best, ok := rep.Winner()
	if !ok {
		// The plan's rule: terminate in a state, never in advice. A run that
		// found nothing still writes the least-bad candidate and says so, and
		// the confidence label is what stops that from being a claim.
		rep.Confidence = ConfidenceLow
		if len(rep.Ranked) > 0 {
			r.warn("no candidate bypassed a blocked target on this line; " +
				"the profile below is the least-bad measurement, not a working strategy")
			rep.Warnings = r.Warnings()
		}
		return rep, err
	}
	rep.Confidence = Confidence(best, len(blocked), r.reps(), rep.NoiseRate)
	return rep, err
}

// capsLabel renders the capability set the sweep ran under.
//
// A zero Cap means "whatever the transport reports", which is what the product
// does and what the CLI passes. Rendering it through Cap.String would write
// "none" into the profile, and a reader would take that to mean the transport
// could do nothing at all — the opposite of what it says.
func capsLabel(c strategy.Cap) string {
	if c == 0 {
		return "transport-default"
	}
	return c.String()
}

func (r *Runner) progress(phase string) {
	if r.o.OnProgress == nil {
		return
	}
	r.mu.Lock()
	done, total := r.done, r.total
	r.mu.Unlock()
	r.progressMu.Lock()
	defer r.progressMu.Unlock()
	r.o.OnProgress(Progress{Phase: phase, Done: done, Total: total, Elapsed: r.now().Sub(r.started)})
}

func hosts(ts []Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.String())
	}
	return out
}

// Tuned renders the report as the profile that will be written.
func (r Report) Tuned() config.Tuned {
	t := config.Tuned{
		Version:     config.TunedVersion,
		CreatedAt:   r.CreatedAt,
		ToolVersion: r.ToolVersion,
		NetworkKey:  r.NetworkKey,
		Caps:        r.Caps,
		Confidence:  r.Confidence,
		NoiseRate:   r.NoiseRate,
		ElapsedMS:   r.Elapsed.Milliseconds(),
		Ladder:      r.Ladder,
		Blocked:     r.Blocked,
		NotBlocked:  r.NotBlocked,
		Warnings:    r.Warnings,
		Classification: config.TunedClassification{
			Shape:            r.Class.Shape.String(),
			FirstRecordLimit: r.Class.FirstRecordLimit,
			SNIEnd:           r.Class.SNIEnd,
			InspectBytes:     r.Class.InspectBytes,
			RSTLatencyMS:     r.Class.RSTLatency.Milliseconds(),
			RecordFrag:       r.Class.RecordFrag,
			TCPSplit:         r.Class.TCPSplit,
			Chunking:         r.Class.Chunking,
			InspectSource: "unmeasured: the ClientHello padding sweep is impossible for a byte " +
				"relay, see PLAN amendment A2",
		},
	}
	if len(t.Ladder) == 0 {
		t.Ladder = []string{""}
	}
	if best, ok := r.Winner(); ok {
		t.Strategy = best.Spec
	}
	for _, o := range r.Matrix.Order() {
		t.Resolvers = append(t.Resolvers, o)
	}
	for _, s := range r.Ranked {
		t.Candidates = append(t.Candidates, config.TunedCandidate{
			Spec:         s.Spec,
			BypassPass:   s.BypassPass,
			BypassTotal:  s.BypassTotal,
			WilsonLo:     s.WilsonLo,
			AllTargets:   s.AllTargets,
			ControlPass:  s.ControlPass,
			ControlTotal: s.ControlTotal,
			FragilePass:  s.FragilePass,
			FragileTotal: s.FragileTotal,
			Determinism:  s.Determinism.String(),
			Segments:     s.Segments,
			MedianRTTMS:  s.MedianRTT.Milliseconds(),
			Discarded:    s.Discarded,
			Unmeasurable: s.Unmeasurable,
		})
	}
	return t
}

// WriteConfig writes the tuned profile.
//
// It refuses to write a profile with no measured ladder rather than leaving a
// file that says "this network was measured" when it was not.
func (r Report) WriteConfig(path string) error {
	if len(r.Blocked) == 0 {
		return fmt.Errorf("probe: refusing to write %s: nothing was measured as blocked here, "+
			"so there is no result to record", path)
	}
	return r.Tuned().Save(path)
}

// Export is the one pasteable line the plan asks for: a strategy someone can
// hand to another person on the same ISP, who verifies it locally with
// `dpb apply` rather than trusting it.
func (r Report) Export() string {
	best, ok := r.Winner()
	if !ok {
		return "# dpb tune found no working strategy on this line"
	}
	return fmt.Sprintf("dpb apply '%s'   # %d/%d bypass, %d/%d controls, confidence %s",
		best.Spec, best.BypassPass, best.BypassTotal, best.ControlPass, best.ControlTotal, r.Confidence)
}

// Text renders the human report.
func (r Report) Text(w io.Writer) error {
	bw := &errWriter{w: w}

	fmt.Fprintf(bw, "dpb tune — %s\n\n", r.CreatedAt.Format(time.RFC3339))

	if len(r.Matrix.Rows) > 0 {
		fmt.Fprintf(bw, "DNS transports (control %s)\n", r.Matrix.Control)
		tw := tabwriter.NewWriter(bw, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  transport\t%s\n", strings.Join(r.Matrix.Names, "\t"))
		for _, row := range r.Matrix.Rows {
			cells := make([]string, 0, len(row.Cells))
			for _, c := range row.Cells {
				cells = append(cells, c.Outcome.String())
			}
			mark := " "
			if row.Clean {
				mark = "*"
			}
			fmt.Fprintf(tw, "%s %s\t%s\n", mark, row.Label, strings.Join(cells, "\t"))
		}
		tw.Flush()
		fmt.Fprintln(bw)
	}

	fmt.Fprintf(bw, "block shape        %s\n", r.Class.Shape)
	if r.Class.SNIEnd > 0 {
		fmt.Fprintf(bw, "first-record limit %d (sniEnd %d)\n", r.Class.FirstRecordLimit, r.Class.SNIEnd)
	}
	fmt.Fprintf(bw, "inspection window  unmeasured (see warnings)\n")
	if r.Class.RSTLatency > 0 {
		fmt.Fprintf(bw, "RST latency        %s\n", r.Class.RSTLatency.Round(time.Millisecond))
	}
	fmt.Fprintf(bw, "blocked            %s\n", orNone(r.Blocked))
	fmt.Fprintf(bw, "not blocked        %s\n", orNone(r.NotBlocked))
	fmt.Fprintf(bw, "noise              %.1f%% of rounds discarded\n\n", 100*r.NoiseRate)

	if len(r.Ranked) > 0 {
		fmt.Fprintln(bw, "ranked candidates")
		tw := tabwriter.NewWriter(bw, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  #\tstrategy\tbypass\twilson\tcontrols\tfragile\tkind\tseg\trtt")
		for i, s := range r.Ranked {
			if s.Unmeasurable {
				fmt.Fprintf(tw, "  %d\t%s\tUNMEASURABLE — the emitter refused to build it here\t\t\t\t\t\t\n",
					i+1, s.Label())
				continue
			}
			fmt.Fprintf(tw, "  %d\t%s\t%d/%d\t%.2f\t%d/%d\t%d/%d\t%s\t%d\t%s\n",
				i+1, s.Label(), s.BypassPass, s.BypassTotal, s.WilsonLo,
				s.ControlPass, s.ControlTotal, s.FragilePass, s.FragileTotal,
				s.Determinism, s.Segments, roundMS(s.MedianRTT))
		}
		tw.Flush()
		fmt.Fprintln(bw)
	}

	if best, ok := r.Winner(); ok {
		fmt.Fprintf(bw, "winner     %s  (confidence %s)\n", best.Label(), r.Confidence)
		fmt.Fprintf(bw, "ladder     %s\n", strings.Join(labels(r.Ladder), " → "))
	} else {
		fmt.Fprintf(bw, "winner     none — no candidate bypassed a blocked target here\n")
	}

	if len(r.Class.Evidence) > 0 {
		fmt.Fprintln(bw, "\nevidence")
		for _, e := range r.Class.Evidence {
			fmt.Fprintf(bw, "  %s\n    via %s: %s\n", e.Claim, e.Method, e.Observed)
		}
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(bw, "\nwarnings")
		for _, s := range r.Warnings {
			fmt.Fprintf(bw, "  - %s\n", s)
		}
	}
	return bw.err
}

// reportJSON is the wire shape, kept as its own type because the format is a
// contract with whoever parses `dpb tune --json` and must not drift every time
// an internal field moves.
type reportJSON struct {
	CreatedAt   string          `json:"created_at"`
	ToolVersion string          `json:"tool_version,omitempty"`
	NetworkKey  string          `json:"network_key,omitempty"`
	Caps        string          `json:"caps,omitempty"`
	Shape       string          `json:"shape"`
	Confidence  string          `json:"confidence"`
	NoiseRate   float64         `json:"noise_rate"`
	ElapsedMS   int64           `json:"elapsed_ms"`
	Blocked     []string        `json:"blocked"`
	NotBlocked  []string        `json:"not_blocked"`
	Winner      string          `json:"winner,omitempty"`
	Ladder      []string        `json:"ladder"`
	DNS         []dnsRowJSON    `json:"dns"`
	Class       classJSON       `json:"classification"`
	Ranked      []scoreJSON     `json:"ranked"`
	Evidence    []evidenceJSON  `json:"evidence"`
	Warnings    []string        `json:"warnings,omitempty"`
	Trials      []trialJSONWire `json:"trials,omitempty"`
}

type dnsRowJSON struct {
	Label     string            `json:"label"`
	Transport string            `json:"transport"`
	Clean     bool              `json:"clean"`
	Cells     map[string]string `json:"cells"`
}

type classJSON struct {
	Shape            string `json:"shape"`
	FirstRecordLimit int    `json:"first_record_limit"`
	SNIEnd           int    `json:"sni_end"`
	InspectBytes     int    `json:"inspect_bytes"`
	InspectMeasured  bool   `json:"inspect_bytes_measured"`
	RSTLatencyMS     int64  `json:"rst_latency_ms"`
	RecordFrag       bool   `json:"record_frag"`
	TCPSplit         bool   `json:"tcp_split"`
	Chunking         bool   `json:"chunking"`
}

type scoreJSON struct {
	Spec         string                `json:"spec"`
	BypassPass   int                   `json:"bypass_pass"`
	BypassTotal  int                   `json:"bypass_total"`
	WilsonLo     float64               `json:"wilson_lo"`
	AllTargets   bool                  `json:"all_targets"`
	ControlPass  int                   `json:"control_pass"`
	ControlTotal int                   `json:"control_total"`
	FragilePass  int                   `json:"fragile_pass"`
	FragileTotal int                   `json:"fragile_total"`
	Determinism  string                `json:"determinism"`
	Segments     int                   `json:"segments"`
	MedianRTTMS  int64                 `json:"median_rtt_ms"`
	Discarded    int                   `json:"discarded"`
	Unmeasurable bool                  `json:"unmeasurable"`
	PerTarget    map[string]targetJSON `json:"per_target,omitempty"`
}

type targetJSON struct {
	Pass  int `json:"pass"`
	Total int `json:"total"`
}

type evidenceJSON struct {
	Claim    string `json:"claim"`
	Method   string `json:"method"`
	Observed string `json:"observed"`
	At       string `json:"at"`
}

type trialJSONWire struct {
	Spec     string `json:"spec"`
	Host     string `json:"host"`
	Kind     string `json:"kind"`
	Round    int    `json:"round"`
	Verdict  string `json:"verdict"`
	Scorable bool   `json:"scorable"`
	Latency  int64  `json:"latency_ms"`
	Err      string `json:"error,omitempty"`
}

// JSON emits the whole session. It is the field-report format: the thing a user
// on an unmeasured Turkish ISP can send back, and the reason the tool does not
// need telemetry to learn.
func (r Report) JSON(w io.Writer) error {
	o := reportJSON{
		CreatedAt:   r.CreatedAt.UTC().Format(time.RFC3339Nano),
		ToolVersion: r.ToolVersion,
		NetworkKey:  r.NetworkKey,
		Caps:        r.Caps,
		Shape:       r.Class.Shape.String(),
		Confidence:  r.Confidence,
		NoiseRate:   r.NoiseRate,
		ElapsedMS:   r.Elapsed.Milliseconds(),
		Blocked:     nonNil(r.Blocked),
		NotBlocked:  nonNil(r.NotBlocked),
		Ladder:      nonNil(r.Ladder),
		Class: classJSON{
			Shape:            r.Class.Shape.String(),
			FirstRecordLimit: r.Class.FirstRecordLimit,
			SNIEnd:           r.Class.SNIEnd,
			InspectBytes:     r.Class.InspectBytes,
			// Explicitly false in this build. A consumer must be able to tell
			// "the window is zero" from "we could not measure the window", and
			// a bare 0 cannot say which.
			InspectMeasured: false,
			RSTLatencyMS:    r.Class.RSTLatency.Milliseconds(),
			RecordFrag:      r.Class.RecordFrag,
			TCPSplit:        r.Class.TCPSplit,
			Chunking:        r.Class.Chunking,
		},
		Warnings: r.Warnings,
	}
	if best, ok := r.Winner(); ok {
		o.Winner = best.Spec
	}
	for _, row := range r.Matrix.Rows {
		cells := make(map[string]string, len(row.Cells))
		for _, c := range row.Cells {
			cells[c.Name] = c.Outcome.String()
		}
		o.DNS = append(o.DNS, dnsRowJSON{
			Label: row.Label, Transport: row.Transport, Clean: row.Clean, Cells: cells,
		})
	}
	for _, s := range r.Ranked {
		sj := scoreJSON{
			Spec: s.Spec, BypassPass: s.BypassPass, BypassTotal: s.BypassTotal,
			WilsonLo: s.WilsonLo, AllTargets: s.AllTargets,
			ControlPass: s.ControlPass, ControlTotal: s.ControlTotal,
			FragilePass: s.FragilePass, FragileTotal: s.FragileTotal,
			Determinism: s.Determinism.String(), Segments: s.Segments,
			MedianRTTMS: s.MedianRTT.Milliseconds(), Discarded: s.Discarded,
			Unmeasurable: s.Unmeasurable,
		}
		if len(s.PerTarget) > 0 {
			sj.PerTarget = make(map[string]targetJSON, len(s.PerTarget))
			for h, ts := range s.PerTarget {
				sj.PerTarget[h] = targetJSON{Pass: ts.Pass, Total: ts.Total}
			}
		}
		o.Ranked = append(o.Ranked, sj)
	}
	for _, e := range r.Class.Evidence {
		o.Evidence = append(o.Evidence, evidenceJSON{
			Claim: e.Claim, Method: e.Method, Observed: e.Observed,
			At: e.At.UTC().Format(time.RFC3339Nano),
		})
	}
	for _, t := range r.Trials {
		o.Trials = append(o.Trials, trialJSONWire{
			Spec: t.Spec, Host: t.Target.Host, Kind: t.Target.Kind.String(),
			Round: t.Round, Verdict: t.Verdict.String(), Scorable: t.Verdict.Scorable(),
			Latency: t.Latency.Milliseconds(), Err: oneLine(t.Err),
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(o); err != nil {
		return fmt.Errorf("probe: write JSON: %w", err)
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}

func labels(specs []string) []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, label(s))
	}
	return out
}

func roundMS(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(time.Millisecond).String()
}

// errWriter latches the first write error so a long report does not need a
// check on every line and does not silently truncate.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(b []byte) (int, error) {
	if e.err != nil {
		return len(b), nil
	}
	n, err := e.w.Write(b)
	if err != nil {
		e.err = err
	}
	return n, err
}
