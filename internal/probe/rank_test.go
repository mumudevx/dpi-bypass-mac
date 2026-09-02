package probe_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// docs is the real op documentation. Ranking key 3 reads determinism from it,
// so a stub table would let a composite hiding chunk:size behind tlsfrag score
// as rule-based.
func docs() []strategy.OpDoc { return reg.Docs() }

func blockedTargets(hosts ...string) []probe.Target {
	out := make([]probe.Target, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, probe.Target{Host: h, Kind: probe.TargetBlocked, Addr: "203.0.113.1"})
	}
	return out
}

// trials builds n trials of one spec against one target with one verdict.
func trials(spec, host string, kind probe.TargetKind, v probe.Verdict, n int) []probe.Trial {
	out := make([]probe.Trial, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, probe.Trial{
			Spec:    spec,
			Target:  probe.Target{Host: host, Kind: kind, Addr: "203.0.113.1"},
			Round:   i + 1,
			Verdict: v,
			Latency: 20 * time.Millisecond,
		})
	}
	return out
}

// TestRankRefusesAOneTargetWinner is the plan's clause verbatim: a candidate
// that passes target A and fails target B must not be ranked first even when A
// was probed first.
//
// It is the whole reason ranking is by a Wilson lower bound over pooled trials
// rather than by "did it work on the first host we tried".
func TestRankRefusesAOneTargetWinner(t *testing.T) {
	blocked := blockedTargets("discord.com", "discord.gg")

	var ts []probe.Trial
	// A is probed FIRST and passes; B fails. This is the trap.
	ts = append(ts, trials("chunk:size=12", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)...)
	ts = append(ts, trials("chunk:size=12", "discord.gg", probe.TargetBlocked, probe.VerdictReset, 3)...)
	// The intersection candidate is probed second and passes both.
	ts = append(ts, trials("tlsfrag:pos=snimid", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)...)
	ts = append(ts, trials("tlsfrag:pos=snimid", "discord.gg", probe.TargetBlocked, probe.VerdictPass, 3)...)

	got := probe.Rank(ts, blocked, docs())
	if len(got) != 2 {
		t.Fatalf("scores = %d, want 2", len(got))
	}
	if got[0].Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("rank 1 = %q, want tlsfrag:pos=snimid (%s)", got[0].Spec, specList(got))
	}
	if got[0].WilsonLo <= got[1].WilsonLo {
		t.Errorf("WilsonLo %.3f (both targets) must exceed %.3f (one target)",
			got[0].WilsonLo, got[1].WilsonLo)
	}
	if !got[0].AllTargets {
		t.Error("the intersection candidate is not marked AllTargets")
	}
	if got[1].AllTargets {
		t.Error("a candidate that failed a target is marked AllTargets")
	}
}

// TestRankExcludesDiscardedRounds: a round whose interleaved control failed is
// discarded, never scored. Counting it would attribute the network going down
// to the candidate.
func TestRankExcludesDiscardedRounds(t *testing.T) {
	blocked := blockedTargets("discord.com")

	ts := trials("tlsfrag:pos=snimid", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)
	ts = append(ts, trials("tlsfrag:pos=snimid", "discord.com", probe.TargetBlocked, probe.VerdictControlDown, 5)...)

	got := probe.Rank(ts, blocked, docs())
	if len(got) != 1 {
		t.Fatalf("scores = %d, want 1", len(got))
	}
	if got[0].BypassTotal != 3 || got[0].BypassPass != 3 {
		t.Errorf("bypass = %d/%d, want 3/3: the five discarded rounds must not reach the denominator",
			got[0].BypassPass, got[0].BypassTotal)
	}
	if got[0].Discarded != 5 {
		t.Errorf("Discarded = %d, want 5", got[0].Discarded)
	}
	if lo, _ := probe.Wilson(3, 3, probe.Z95); math.Abs(got[0].WilsonLo-lo) > 1e-9 {
		t.Errorf("WilsonLo = %.4f, want the 3/3 bound %.4f — the discarded rounds moved it",
			got[0].WilsonLo, lo)
	}
}

// TestRankLocalErrorsAreNeverScored: a strategy that never reached the wire has
// not been measured, and reporting it as blocked is how a prober poisons its
// own ranking.
func TestRankLocalErrorsAreNeverScored(t *testing.T) {
	blocked := blockedTargets("discord.com")

	var ts []probe.Trial
	ts = append(ts, trials("chunk:size=4", "discord.com", probe.TargetBlocked, probe.VerdictLocalError, 3)...)
	ts = append(ts, trials("chunk:size=12", "discord.com", probe.TargetBlocked, probe.VerdictReset, 3)...)

	got := probe.Rank(ts, blocked, docs())
	four := scoreOf(t, got, "chunk:size=4")
	if four.BypassTotal != 0 || !four.Unmeasurable || four.LocalErrors != 3 {
		t.Errorf("chunk:size=4 = %d/%d unmeasurable=%v localErrors=%d; want 0/0 unmeasurable with 3 local errors",
			four.BypassPass, four.BypassTotal, four.Unmeasurable, four.LocalErrors)
	}
	// A candidate that was measured and failed still outranks one that was
	// never emitted: the failure is evidence and the refusal is not.
	if rankOf(got, "chunk:size=12") >= rankOf(got, "chunk:size=4") {
		t.Errorf("unmeasurable chunk:size=4 ranked %d, measured chunk:size=12 ranked %d",
			rankOf(got, "chunk:size=4"), rankOf(got, "chunk:size=12"))
	}
}

// TestRankPrefersWorkingControls reproduces the key that decides
// MEASUREMENTS.md §5.3's ladder order: chunk-12 keeps 8/8 controls, oob-at-1
// falls to 6/8, and both bypass 6/6.
func TestRankPrefersWorkingControls(t *testing.T) {
	blocked := blockedTargets("discord.com", "discord.gg", "cdn.discordapp.com")

	var ts []probe.Trial
	for _, spec := range []string{"chunk:size=12", "oob:pos=1"} {
		for _, h := range []string{"discord.com", "discord.gg", "cdn.discordapp.com"} {
			ts = append(ts, trials(spec, h, probe.TargetBlocked, probe.VerdictPass, 2)...)
		}
	}
	ts = append(ts, trials("chunk:size=12", "cloudflare.com", probe.TargetControl, probe.VerdictPass, 8)...)
	ts = append(ts, trials("oob:pos=1", "cloudflare.com", probe.TargetControl, probe.VerdictPass, 6)...)
	ts = append(ts, trials("oob:pos=1", "cloudflare.com", probe.TargetControl, probe.VerdictReset, 2)...)

	got := probe.Rank(ts, blocked, docs())
	if got[0].Spec != "chunk:size=12" {
		t.Errorf("rank 1 = %q, want chunk:size=12: 8/8 controls must beat 6/8 before any other key",
			got[0].Spec)
	}
}

// TestRankCountsAFragileAlertAsAFailure: MEASUREMENTS.md §5 scores
// yapikredi.com.tr's "remote error: tls: illegal parameter" as a REGRESSION
// under record splitting. Discarding it as a server condition — which is the
// right call on the bypass axis — would empty the denominator of the axis that
// decides the architecture.
func TestRankCountsAFragileAlertAsAFailure(t *testing.T) {
	blocked := blockedTargets("discord.com")

	var ts []probe.Trial
	ts = append(ts, trials("tlsfrag:pos=snimid", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)...)
	ts = append(ts, trials("tlsfrag:pos=snimid", "www.yapikredi.com.tr", probe.TargetFragile,
		probe.VerdictHandshakeFail, 4)...)
	// The same verdict against a BLOCKED target stays unscorable: there it is
	// the origin refusing us, and says nothing about the DPI.
	ts = append(ts, trials("tlsfrag:pos=snimid", "discord.com", probe.TargetBlocked,
		probe.VerdictHandshakeFail, 4)...)

	got := probe.Rank(ts, blocked, docs())
	s := got[0]
	if s.FragileTotal != 4 || s.FragilePass != 0 {
		t.Errorf("fragile = %d/%d, want 0/4", s.FragilePass, s.FragileTotal)
	}
	if s.BypassTotal != 3 {
		t.Errorf("bypass denominator = %d, want 3: a handshake failure against a blocked target "+
			"is a server condition, not a strategy result", s.BypassTotal)
	}
}

// TestRankIgnoresTargetsTheBaselineDropped: a "blocked" target that turned out
// to reach its origin plain must not inflate every candidate's bypass rate.
func TestRankIgnoresTargetsTheBaselineDropped(t *testing.T) {
	blocked := blockedTargets("discord.com") // discord.media was dropped

	var ts []probe.Trial
	ts = append(ts, trials("plain", "discord.com", probe.TargetBlocked, probe.VerdictReset, 3)...)
	ts = append(ts, trials("plain", "discord.media", probe.TargetBlocked, probe.VerdictPass, 3)...)

	got := probe.Rank(ts, blocked, docs())
	if got[0].BypassTotal != 3 || got[0].BypassPass != 0 {
		t.Errorf("bypass = %d/%d, want 0/3", got[0].BypassPass, got[0].BypassTotal)
	}
}

// TestRankIsStable: the same data must produce the same order, run after run,
// or two operators comparing notes cannot tell a real difference from a shuffle.
func TestRankIsStable(t *testing.T) {
	blocked := blockedTargets("discord.com")
	var ts []probe.Trial
	for _, spec := range []string{"tlsfrag:pos=snimid", "tlsevery:period=64", "chunk:size=12"} {
		ts = append(ts, trials(spec, "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)...)
		ts = append(ts, trials(spec, "cloudflare.com", probe.TargetControl, probe.VerdictPass, 3)...)
	}
	first := specList(probe.Rank(ts, blocked, docs()))
	for i := 0; i < 5; i++ {
		if got := specList(probe.Rank(ts, blocked, docs())); got != first {
			t.Fatalf("run %d ordered %s, first run ordered %s", i, got, first)
		}
	}
}

// TestRankPrefersACutInsideTheHostname reproduces MEASUREMENTS.md §3.3's
// "strictly dominant cut position". Two reframers that tie on every measured
// axis are separated by where the cut landed relative to the hostname, and the
// position furthest from both edges wins.
func TestRankPrefersACutInsideTheHostname(t *testing.T) {
	blocked := blockedTargets("discord.com")

	mid := trials("tlsfrag:pos=snimid", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)
	edge := trials("tlsfrag:pos=sniend-1", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)
	before := trials("tlsevery:period=64", "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)
	for i := range mid {
		mid[i].SNIStart, mid[i].SNIEnd, mid[i].RecordEnd = 112, 122, 117
		edge[i].SNIStart, edge[i].SNIEnd, edge[i].RecordEnd = 112, 122, 121
		before[i].SNIStart, before[i].SNIEnd, before[i].RecordEnd = 112, 122, 64
	}
	ts := append(append(append([]probe.Trial(nil), edge...), before...), mid...)

	got := probe.Rank(ts, blocked, docs())
	if got[0].Spec != "tlsfrag:pos=snimid" {
		t.Errorf("rank 1 = %q, want tlsfrag:pos=snimid (%s)", got[0].Spec, specList(got))
	}
	if got[0].CutMargin != 5 {
		t.Errorf("CutMargin = %d, want 5 (cut 117 in [112,122))", got[0].CutMargin)
	}
	if s := scoreOf(t, got, "tlsevery:period=64"); s.CutMargin != 0 {
		t.Errorf("a cut before the hostname has margin %d, want 0", s.CutMargin)
	}
}

// TestLadderEscalatesThroughDistinctMechanisms. Measured live on Türk Telekom,
// the four best bypassing candidates were four cut positions of tlsfrag, so a
// ladder built from the top of the ranking was one emitter four times over. An
// origin that rejects a handshake spanning two records rejects all four
// identically, which makes rungs 3 and 4 decoration.
func TestLadderEscalatesThroughDistinctMechanisms(t *testing.T) {
	blocked := blockedTargets("discord.com")
	var ts []probe.Trial
	// Ordered so the tlsfrag variants rank above the other mechanisms: they
	// keep a clean fragile record while chunk breaks one control trial.
	for _, spec := range []string{
		"tlsfrag:pos=snimid", "tlsfrag:pos=sniend-1", "tlsfrag:pos=snistart+1",
		"tlsevery:period=64", "chunk:size=12",
	} {
		ts = append(ts, trials(spec, "discord.com", probe.TargetBlocked, probe.VerdictPass, 3)...)
	}

	rep := probe.Report{Ranked: probe.Rank(ts, blocked, docs())}
	rep.Ladder = probe.LadderFrom(rep.Ranked, probe.LadderDepth)

	if len(rep.Ladder) != probe.LadderDepth {
		t.Fatalf("ladder = %q, want %d rungs", rep.Ladder, probe.LadderDepth)
	}
	if rep.Ladder[0] != "" {
		t.Errorf("rung 1 = %q, want plain", rep.Ladder[0])
	}
	seen := map[string]bool{}
	for _, rung := range rep.Ladder[1:] {
		fam := rung
		if i := strings.IndexByte(fam, ':'); i >= 0 {
			fam = fam[:i]
		}
		if seen[fam] {
			t.Errorf("ladder %q repeats the %s mechanism; escalating to the same emitter at a "+
				"different parameter buys nothing against an origin that rejected it", rep.Ladder, fam)
		}
		seen[fam] = true
	}
	if rep.Ladder[1] != rep.Ranked[0].Spec {
		t.Errorf("rung 2 = %q, want the top-ranked candidate %q", rep.Ladder[1], rep.Ranked[0].Spec)
	}
}
