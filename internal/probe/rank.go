package probe

import (
	"sort"
	"strings"
	"time"

	"github.com/mumudevx/dpb/internal/strategy"
)

// Score is one candidate's two-axis result.
type Score struct {
	Spec string

	BypassPass  int
	BypassTotal int
	WilsonLo    float64
	// AllTargets means the candidate passed at least once against EVERY blocked
	// target, which is the cross-target intersection §5.1 exists to protect. It
	// is reported rather than used as a disqualifier: the Wilson lower bound
	// already pushes a one-target candidate below a three-target one, and a
	// hard gate would throw away a real result on a run whose third target went
	// down.
	AllTargets bool

	ControlPass  int
	ControlTotal int
	FragilePass  int
	FragileTotal int

	Determinism strategy.Determinism
	Segments    int
	Caps        strategy.Cap
	MedianRTT   time.Duration
	Discarded   int

	// CutMargin is how far the emitted first-record boundary landed from the
	// NEAREST edge of the SNI hostname, in bytes, measured from the bytes the
	// plan actually emitted. 0 means the cut was not inside the hostname at all.
	//
	// It is the only ranking input this file adds to the plan's seven keys, and
	// it exists because MEASUREMENTS.md §3.3 records a strictly dominant cut
	// position — "inside the hostname (sniMid)" — that the other six keys
	// cannot see. Every reframing position that satisfies the record rule ties
	// on control rate, on bypass rate, on determinism, on fragile-host
	// compatibility and on segment count, so without this the winner among them
	// would be decided by whichever spec sorts first alphabetically.
	//
	// A cut inside the hostname is dominant for two measured reasons. It splits
	// the hostname itself, so it also defeats a middlebox that string-matches
	// the raw stream with no record awareness (§3.3). And §3.2's boundary was
	// measured to sit exactly at sniEnd while §4 states plainly that the rule
	// "is not a law" — so the position furthest from both edges is the one that
	// survives the largest error in either direction, which is what makes
	// sniMid preferable to sniEnd-1 rather than merely equal to it.
	CutMargin int

	// Unmeasurable means no attempt of this candidate ever reached the wire —
	// every one was refused at build time or failed locally. It is NOT the same
	// as blocked, and conflating the two is how a prober poisons its own
	// ranking: chunk sizes the emitter now refuses would otherwise contribute a
	// fake 0/N and drag the whole chunk family down as if the DPI had beaten it.
	Unmeasurable bool
	LocalErrors  int

	// PerTarget is pass/total per blocked target host, so a reader can see the
	// intersection rather than take AllTargets on trust.
	PerTarget map[string]TargetScore
}

// TargetScore is one candidate's result against one target.
type TargetScore struct {
	Pass  int
	Total int
}

// Label renders the spec the way a report prints it.
func (s Score) Label() string {
	if s.Spec == "" {
		return "plain"
	}
	return s.Spec
}

// ControlRate and BypassRate are convenience accessors for report rendering.
func (s Score) ControlRate() float64 { return rate(s.ControlPass, s.ControlTotal) }
func (s Score) BypassRate() float64  { return rate(s.BypassPass, s.BypassTotal) }
func (s Score) FragileRate() float64 { return rate(s.FragilePass, s.FragileTotal) }

func rate(pass, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(pass) / float64(total)
}

// Rank orders candidates on both axes at once.
//
// Precedence, exactly as the plan specifies it:
//
//  1. control pass rate — does the ordinary internet still work;
//  2. bypass Wilson lower bound;
//  3. determinism — a rule beats an empirical constant;
//  4. fragile-host pass rate — compared only when the intervals do not
//     overlap, see cmpFragile;
//     4b. cut margin — the one key added here; see Score.CutMargin;
//  5. fewer segments;
//  6. median latency;
//  7. lexicographic, for run-to-run stability.
//
// with ONE gate ahead of all of them: a candidate with no scorable bypass
// evidence sorts last, whatever its other numbers say. That is not a taste
// preference. A rung the emitter refuses to build produces zero scorable
// trials and would otherwise show a perfect 0/0 control rate, a rule-based
// determinism and one segment — and would rank first on a line where it was
// never emitted at all.
//
// Applied to MEASUREMENTS.md §5.1's matrix this reproduces §5.3: tlsfrag and
// chunk-12 tie at 8/8 controls and 6/6 bypass, tlsfrag wins on determinism;
// oob falls to 6/8 controls and lands below both.
func Rank(ts []Trial, blocked []Target, docs []strategy.OpDoc) []Score {
	byDoc := make(map[string]strategy.OpDoc, len(docs))
	for _, d := range docs {
		byDoc[d.Name] = d
	}
	blockedHosts := make(map[string]bool, len(blocked))
	for _, b := range blocked {
		blockedHosts[b.Host] = true
	}

	order := make([]string, 0, 8)
	acc := make(map[string]*accum, 8)
	for _, t := range ts {
		a := acc[t.Spec]
		if a == nil {
			a = &accum{spec: t.Spec, perTarget: map[string]TargetScore{}}
			acc[t.Spec] = a
			order = append(order, t.Spec)
		}
		a.add(t, blockedHosts)
	}

	out := make([]Score, 0, len(order))
	for _, spec := range order {
		out = append(out, acc[spec].score(byDoc, blocked))
	}
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

type accum struct {
	spec        string
	bypassPass  int
	bypassTotal int
	controlPass int
	controlAll  int
	fragPass    int
	fragAll     int
	discarded   int
	localErrs   int
	segments    int
	cutMargin   int
	latencies   []time.Duration
	perTarget   map[string]TargetScore
}

func (a *accum) add(t Trial, blockedHosts map[string]bool) {
	if t.Verdict == VerdictControlDown {
		a.discarded++
		return
	}
	if t.Verdict == VerdictLocalError {
		a.localErrs++
		return
	}
	if t.Segments > a.segments {
		a.segments = t.Segments
	}
	if m := cutMargin(t); m > a.cutMargin {
		a.cutMargin = m
	}
	if !scorableFor(t) {
		// Not evidence about this candidate on this axis; see scorableFor.
		return
	}
	pass := t.Verdict == VerdictPass
	if pass && t.Latency > 0 {
		a.latencies = append(a.latencies, t.Latency)
	}
	switch t.Target.Kind {
	case TargetControl:
		a.controlAll++
		if pass {
			a.controlPass++
		}
	case TargetFragile:
		a.fragAll++
		if pass {
			a.fragPass++
		}
	default:
		if !blockedHosts[t.Target.Host] {
			// A blocked-kind target that the baseline dropped. It reached its
			// origin plain, so scoring a bypass against it would inflate every
			// candidate equally and inflate a useless one most.
			return
		}
		a.bypassTotal++
		ps := a.perTarget[t.Target.Host]
		ps.Total++
		if pass {
			a.bypassPass++
			ps.Pass++
		}
		a.perTarget[t.Target.Host] = ps
	}
}

func (a *accum) score(byDoc map[string]strategy.OpDoc, blocked []Target) Score {
	s := Score{
		Spec:         a.spec,
		BypassPass:   a.bypassPass,
		BypassTotal:  a.bypassTotal,
		ControlPass:  a.controlPass,
		ControlTotal: a.controlAll,
		FragilePass:  a.fragPass,
		FragileTotal: a.fragAll,
		Segments:     a.segments,
		MedianRTT:    medianDuration(a.latencies),
		Discarded:    a.discarded,
		LocalErrors:  a.localErrs,
		CutMargin:    a.cutMargin,
		PerTarget:    a.perTarget,
	}
	s.WilsonLo, _ = Wilson(a.bypassPass, a.bypassTotal, Z95)
	s.Unmeasurable = a.bypassTotal == 0 && a.controlAll == 0 && a.fragAll == 0
	s.Determinism, s.Caps = specTraits(a.spec, byDoc)

	s.AllTargets = len(blocked) > 0
	for _, b := range blocked {
		if a.perTarget[b.Host].Pass == 0 {
			s.AllTargets = false
			break
		}
	}
	return s
}

// specTraits derives determinism and capability requirements from the op names
// in a spec.
//
// Determinism is rule-based only when EVERY op is, matching
// strategy.Strategy.Determinism: one empirical constant in a pipeline makes the
// whole result an empirical constant, and ranking key 3 must not be fooled by a
// composite that hides chunk:size behind tlsfrag. The empty strategy is
// rule-based — there is no parameter that could have been tuned to today's line.
func specTraits(spec string, byDoc map[string]strategy.OpDoc) (strategy.Determinism, strategy.Cap) {
	det := strategy.DetRuleBased
	var caps strategy.Cap
	for _, tok := range strings.Split(spec, "|") {
		name := strings.TrimSpace(tok)
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		if name == "" {
			continue
		}
		d, ok := byDoc[name]
		if !ok {
			// An op this build cannot describe. Assume the weaker claim rather
			// than the stronger one: an unknown op is not a rule.
			det = strategy.DetEmpirical
			continue
		}
		if d.Determinism == strategy.DetEmpirical {
			det = strategy.DetEmpirical
		}
		caps |= d.Caps
	}
	return det, caps
}

// less implements the ranking precedence. It is a strict weak ordering, so
// sort.SliceStable produces the same list from the same data every time.
func less(a, b Score) bool {
	// Key 0: measured beats unmeasured.
	if am, bm := a.measured(), b.measured(); am != bm {
		return am
	}
	// Key 1: does the ordinary internet still work.
	if c := cmpRate(a.ControlPass, a.ControlTotal, b.ControlPass, b.ControlTotal); c != 0 {
		return c > 0
	}
	// Key 2: bypass Wilson lower bound.
	if a.WilsonLo != b.WilsonLo {
		return a.WilsonLo > b.WilsonLo
	}
	// Key 3: a rule beats a magic number.
	if a.Determinism != b.Determinism {
		return a.Determinism > b.Determinism
	}
	// Key 4: fragile-host compatibility, but only when the difference is larger
	// than the evidence's own noise. See cmpFragile.
	if c := cmpFragile(a, b); c != 0 {
		return c > 0
	}
	// Key 4b: how far the cut landed from the hostname's edges. See CutMargin:
	// this is the one key added to the plan's seven, and it is what reproduces
	// MEASUREMENTS.md §3.3's "strictly dominant cut position".
	if a.CutMargin != b.CutMargin {
		return a.CutMargin > b.CutMargin
	}
	// Key 5: fewer writes — latency, and the XNU small-write guard.
	if a.Segments != b.Segments {
		return segLess(a.Segments, b.Segments)
	}
	// Key 6: median latency, to the millisecond. Rounding is not cosmetic: on a
	// loopback fixture, and between two rungs of the same mechanism on a real
	// line, the sub-millisecond difference is noise, and letting noise decide
	// key 6 would make key 7 — the run-to-run stability key — unreachable.
	if ra, rb := a.MedianRTT.Round(time.Millisecond), b.MedianRTT.Round(time.Millisecond); ra != rb {
		return rttLess(ra, rb)
	}
	// Key 7: lexicographic, so two runs of the same sweep agree.
	return a.Spec < b.Spec
}

func (s Score) measured() bool { return s.BypassTotal > 0 }

// scorableFor decides whether a trial says anything about the candidate, and it
// answers differently on the two axes.
//
// On the BYPASS axis a TLS alert or a bad certificate is a server condition and
// is discarded, exactly as the plan requires: it is evidence about the origin,
// not about the DPI.
//
// On the COMPATIBILITY axes — control and fragile — a handshake failure is the
// measurement. MEASUREMENTS.md §5 scores www.yapikredi.com.tr's "remote error:
// tls: illegal parameter" as a REGRESSION under record splitting, and §5.1's
// fragile column (tlsrec 1/20, oob 0/20) is built from precisely those
// failures. Discarding them there would empty the denominator of the axis that
// decides the architecture and let a bank-breaking emitter score a clean sheet.
func scorableFor(t Trial) bool {
	if t.Verdict.Scorable() {
		return true
	}
	switch t.Target.Kind {
	case TargetFragile, TargetControl:
		return t.Verdict == VerdictHandshakeFail
	default:
		return false
	}
}

// cmpFragile compares two candidates on the fragile axis, and reports a
// difference only when the two 95% intervals do not overlap.
//
// This is the one place where a raw rate comparison is actively wrong, and the
// live line proved it. Measured on Türk Telekom over 30 fragile-host trials,
// tlsfrag:pos=snimid scored 1/30 and tlsevery:period=64 scored 2/30 — a
// one-trial difference inside a noise floor that MEASUREMENTS.md §5.1 already
// establishes for the whole record-splitting family (tlsrec 1/20). Compared as
// raw rates, that single trial promoted the more aggressive emitter — 24
// records rather than 2 — over the one §3.3 records as strictly dominant, and
// it would flip again on the next run.
//
// Key 1 deliberately does NOT do this. A control is an ORDINARY site, and any
// measured breakage of the ordinary internet is a safety signal worth erring
// on even when it is not statistically certain; §5.1's 8/8-versus-6/8 control
// column is exactly the separation the plan expects to decide the ladder. The
// fragile axis is the opposite case: every candidate there is already known to
// be bad, so a difference inside the noise carries no information at all.
func cmpFragile(a, b Score) int {
	if a.FragileTotal == 0 || b.FragileTotal == 0 {
		return 0
	}
	alo, ahi := Wilson(a.FragilePass, a.FragileTotal, Z95)
	blo, bhi := Wilson(b.FragilePass, b.FragileTotal, Z95)
	switch {
	case alo > bhi:
		return 1
	case blo > ahi:
		return -1
	default:
		return 0
	}
}

// cutMargin is the distance from the emitted first-record boundary to the
// nearer edge of the hostname, or 0 when the cut did not land inside it.
func cutMargin(t Trial) int {
	if t.SNIEnd <= t.SNIStart || t.RecordEnd <= t.SNIStart || t.RecordEnd >= t.SNIEnd {
		return 0
	}
	return min(t.RecordEnd-t.SNIStart, t.SNIEnd-t.RecordEnd)
}

// segLess treats an unrecorded segment count as "no evidence" rather than as
// the best possible score. Zero segments would otherwise beat one.
func segLess(a, b int) bool {
	if a == 0 {
		return false
	}
	if b == 0 {
		return true
	}
	return a < b
}

// rttLess treats a zero median the same way: a candidate that never passed has
// no latency sample, and no sample must not win a latency tie-break.
func rttLess(a, b time.Duration) bool {
	if a == 0 {
		return false
	}
	if b == 0 {
		return true
	}
	return a < b
}
