package strategy

import (
	"errors"
	"strings"
	"testing"
)

// The TR ladder is lifted verbatim from MEASUREMENTS.md §5.3. If this test
// changes, the claim it encodes must be re-measured, not re-typed.
func TestTRLadderMatchesTheMeasuredOrder(t *testing.T) {
	want := []string{
		"",                   // plain: 0/6 bypass, 8/8 controls, 20/20 fragile
		"tlsfrag:pos=snimid", // 6/6 bypass, 8/8 controls, 1/20 fragile, rule-based
		"chunk:size=12",      // 6/6 bypass, 8/8 controls, 14/20 fragile
		"oob:pos=1",          // 6/6 bypass, 6/8 controls, 0/20 fragile
		// chunk:size=4 was rung 4 until the emitter began refusing any size
		// whose 15-boundary prefix stops short of the SNI. §3.4's correction
		// note has the arithmetic: 15x4 = 60, and the SNI ends at 127.
	}
	got, err := Ladder("tr")
	if err != nil {
		t.Fatalf("Ladder(tr): %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("tr has %d rungs, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("rung %d = %q, want %q", i+1, got[i].String(), w)
		}
	}

	// Rung 1 is plain because MEASUREMENTS.md §5.2 makes default-direct a
	// correctness requirement: 24% of tested hosts are fragile.
	if !got[0].IsPlain() {
		t.Error("rung 1 must be plain")
	}
	// Rung 2 is the rule-based one. §5.3 and probe ranking key 3 both put a
	// rule ahead of a constant that happened to work today.
	if got[1].Determinism() != DetRuleBased {
		t.Error("rung 2 must be the rule-based emitter")
	}
	// And it must be a single write: §3.1 measured two records in ONE TCP
	// segment at 3/3, so rung 2 needs no timing and no socket options.
	payload, m := measuredFixture()
	p, err := got[1].Build(payload, m, allCaps, DefaultBudget())
	if err != nil {
		t.Fatalf("rung 2 does not build: %v", err)
	}
	if p.WriteCount() != 1 {
		t.Errorf("rung 2 emits %d writes, want 1", p.WriteCount())
	}
}

// disorder is 0/10 and split is 0/5 on this line (§3.1, §3.5), so they are
// registered, tested and deliberately absent from the shipped ladder — but
// still swept by the prober, because another ISP may differ.
func TestMeasuredZeroScorersAreNotInTheShippedLadders(t *testing.T) {
	for _, name := range []string{"tr", "global"} {
		specs, ok := LadderSpecs(name)
		if !ok {
			t.Fatalf("no ladder %q", name)
		}
		for _, s := range specs {
			for _, banned := range []string{"disorder", "split:"} {
				if strings.Contains(s, banned) {
					t.Errorf("ladder %q rung %q contains %q, which measured 0 on TT", name, s, banned)
				}
			}
		}
	}
	full, _ := LadderSpecs("probe-full")
	var sawDisorder, sawSplit bool
	for _, s := range full {
		sawDisorder = sawDisorder || strings.Contains(s, "disorder")
		sawSplit = sawSplit || strings.Contains(s, "split:")
	}
	if !sawDisorder || !sawSplit {
		t.Error("probe-full must still sweep disorder and split: the prober measures rather than assumes")
	}
}

// oob is 0/20 against fragile terminators (§5.1), which is too destructive to
// reach for on a line nobody has measured.
func TestGlobalLadderOmitsOOB(t *testing.T) {
	specs, _ := LadderSpecs("global")
	for _, s := range specs {
		if strings.HasPrefix(s, "oob") {
			t.Fatalf("the global ladder must not include %q", s)
		}
	}
	if len(specs) > 5 {
		t.Errorf("the global ladder has %d rungs; max_attempts is 5", len(specs))
	}
}

// Every shipped ladder rung must parse against the registered op set and be
// stable under canonicalisation. This is what makes a typo in the data a
// failing test rather than a runtime surprise on rung 4.
func TestEveryShippedLadderRungIsStable(t *testing.T) {
	for _, name := range LadderNames() {
		rungs, err := Ladder(name)
		if err != nil {
			t.Fatalf("Ladder(%q): %v", name, err)
		}
		if len(rungs) == 0 {
			t.Fatalf("ladder %q is empty", name)
		}
		seen := make(map[string]bool, len(rungs))
		for i, r := range rungs {
			again, err := Parse(r.String())
			if err != nil {
				t.Errorf("%s rung %d (%q) does not re-parse: %v", name, i+1, r.String(), err)
				continue
			}
			if again.String() != r.String() {
				t.Errorf("%s rung %d is not canonical: %q -> %q", name, i+1, r.String(), again.String())
			}
			if seen[r.String()] {
				t.Errorf("%s repeats rung %q; a ladder that retries the same thing wastes an attempt", name, r.String())
			}
			seen[r.String()] = true
		}
	}
}

func TestLadderSpecsIsACopy(t *testing.T) {
	a, ok := LadderSpecs("tr")
	if !ok {
		t.Fatal("no tr ladder")
	}
	a[0] = "tampered"
	b, _ := LadderSpecs("tr")
	if b[0] != "" {
		t.Fatal("LadderSpecs handed out the shipped slice, not a copy")
	}
}

func TestLadderUnknownName(t *testing.T) {
	if _, ok := LadderSpecs("nope"); ok {
		t.Fatal("LadderSpecs invented a ladder")
	}
	_, err := Ladder("nope")
	if !errors.Is(err, ErrUnknownLadder) {
		t.Fatalf("got %v", err)
	}
	for _, name := range LadderNames() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error must list %q: %v", name, err)
		}
	}
}

func TestLadderNamesAreSorted(t *testing.T) {
	got := LadderNames()
	if len(got) != 3 {
		t.Fatalf("LadderNames = %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("LadderNames must be sorted: %v", got)
		}
	}
}

func TestLadderReportsAnUnregisteredOp(t *testing.T) {
	// A build whose op set does not cover a ladder must fail at load, not on
	// the rung the user finally needs.
	r := NewRegistry()
	_, err := r.Ladder("tr")
	if !errors.Is(err, ErrUnknownOp) {
		t.Fatalf("got %v, want ErrUnknownOp", err)
	}
	if !strings.Contains(err.Error(), "rung 2") {
		t.Errorf("the error must name the rung: %v", err)
	}
}

func TestParseLadder(t *testing.T) {
	byName, err := ParseLadder("tr")
	if err != nil || len(byName) != 4 {
		t.Fatalf("ParseLadder(tr) = %d rungs, %v", len(byName), err)
	}
	if _, err := ParseLadder(" tr "); err != nil {
		t.Errorf("ParseLadder must trim: %v", err)
	}

	list, err := ParseLadder("plain,tlsfrag:pos=sniend-1,chunk:size=4")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || !list[0].IsPlain() || list[1].String() != "tlsfrag:pos=sniend-1" {
		t.Fatalf("ParseLadder list = %v", list)
	}

	// A single spec is a one-rung ladder.
	one, err := ParseLadder("chunk:size=12")
	if err != nil || len(one) != 1 {
		t.Fatalf("ParseLadder(chunk:size=12) = %v, %v", one, err)
	}
	// A bare op name is a spec too.
	if _, err := ParseLadder("hostcase"); err != nil {
		t.Errorf("ParseLadder(hostcase): %v", err)
	}

	if _, err := ParseLadder(""); !errors.Is(err, ErrUnknownLadder) {
		t.Errorf("empty: %v", err)
	}
	// A bare identifier that is neither a ladder nor an op reads as a typoed
	// ladder name; "unknown op" would send the reader in the wrong direction.
	if _, err := ParseLadder("turkey"); !errors.Is(err, ErrUnknownLadder) {
		t.Errorf("ParseLadder(turkey) = %v, want ErrUnknownLadder", err)
	}
	if _, err := ParseLadder("chunk:size=12,nosuchop"); !errors.Is(err, ErrUnknownOp) {
		t.Errorf("ParseLadder with a bad rung: %v", err)
	}
}

// probe-full sweeps the exact discrete points MEASUREMENTS.md §3.4 measured,
// because that curve is non-monotonic: a binary search over chunk size would
// converge on a point the data does not support.
func TestProbeFullSweepsTheMeasuredPoints(t *testing.T) {
	specs, _ := LadderSpecs("probe-full")
	have := make(map[string]bool, len(specs))
	for _, s := range specs {
		have[s] = true
	}
	for _, want := range []string{
		"chunk:size=1", "chunk:size=2", "chunk:size=3", "chunk:size=4", "chunk:size=5",
		"chunk:size=8", "chunk:size=12", "chunk:size=20", "chunk:size=35", "chunk:size=40",
		"chunk:size=60", "chunk:size=120",
		"tlsfrag:pos=snistart-20", "tlsfrag:pos=snistart-1", "tlsfrag:pos=snistart",
		"tlsfrag:pos=snistart+1", "tlsfrag:pos=snimid", "tlsfrag:pos=sniend-1",
		"tlsevery:period=16", "tlsevery:period=64", "tlsevery:period=128", "tlsevery:period=256",
		"oob:pos=1", "oob:pos=3",
		"tlsfrag:pos=snimid|chunk:size=12", "tlsevery:period=64|chunk:size=4",
		"hostcase|hostdot|chunk:size=12", "hostpad",
	} {
		if !have[want] {
			t.Errorf("probe-full is missing %q", want)
		}
	}
	// The sweep must not include a cut the validator will always refuse: a rung
	// that can never emit is a wasted probe attempt whose only output is a
	// LOCAL-ERROR line.
	//
	// This is a semantic check, not a pattern match. The clause it replaces
	// searched for a literal double quote inside a spec string
	// (`strings.Contains(s, "tlsfrag:pos=sniend\"")`), which no spec can ever
	// contain, so only an exact `pos=sniend` suffix was caught: adding
	// `tlsfrag:pos=sniend+200` left this test PASSing, and the only complaint
	// anywhere was TestGoldenPlans printing it as a paste-ready expectation.
	for _, s := range alwaysRefusedCuts(specs) {
		t.Errorf("probe-full includes %q, which ErrCutAfterSNI always refuses", s)
	}
}

// alwaysRefusedCuts returns the specs whose plan can never be built, because
// the cut they name lands at or past sniEnd for EVERY hello.
//
// "Every hello" is why this walks a family of fixtures rather than one. A cut
// anchored to the SNI (tlsfrag:pos=sniend+200) is refused whatever the geometry
// and belongs on this list; a fixed period (tlsevery:period=128) is refused
// only when the hostname happens to end before it, and builds fine for a hello
// whose SNI sits deeper — a real case, since a Chrome hello with a randomised
// extension order and an MLKEM key share can carry the name well past 128.
// Flagging those would delete measured points from the sweep: MEASUREMENTS.md
// §3 measured every-16, every-64 and every-256, and §3.5 requires the prober to
// measure the emitter this tool ships rather than to assume.
//
// Errors other than ErrCutAfterSNI are deliberately ignored. The sweep is meant
// to contain rungs that do not apply to a TLS hello (the Host-header ops) and
// rungs that are expected to fail on the wire; this guard is only about a cut
// the validator itself always rejects.
func alwaysRefusedCuts(specs []string) []string {
	// §3.2's own geometry, plus two hellos carrying the name progressively
	// deeper into the body.
	fixtures := [][2]int{{112, 122}, {300, 330}, {600, 640}}

	var bad []string
	for _, spec := range specs {
		if spec == "" {
			continue
		}
		st, err := Parse(spec)
		if err != nil {
			continue // TestEveryShippedLadderRungIsStable owns parse failures
		}
		refusedEverywhere := true
		for _, f := range fixtures {
			payload, m := tlsFixture(1497, f[0], f[1])
			if _, err := st.Build(payload, m, allCaps, DefaultBudget()); !errors.Is(err, ErrCutAfterSNI) {
				refusedEverywhere = false
				break
			}
		}
		if refusedEverywhere {
			bad = append(bad, spec)
		}
	}
	return bad
}

// TestAlwaysRefusedCutsActuallyFires is the guard's own regression test. The
// clause it replaces was dead for the life of the tree and nothing noticed,
// which is the failure mode a guard with no meta-test always has.
func TestAlwaysRefusedCutsActuallyFires(t *testing.T) {
	// Every one of these is anchored past sniEnd, so it is refused whatever the
	// hello looks like. sniend+200 and sniend+1 are exactly the shapes the old
	// pattern match missed: it searched a spec string for a literal quote.
	bad := []string{"tlsfrag:pos=sniend", "tlsfrag:pos=sniend+200", "tlsfrag:pos=sniend+1"}
	if got := alwaysRefusedCuts(bad); len(got) != len(bad) {
		t.Fatalf("guard caught %v, want all of %v", got, bad)
	}

	// And it must not flag a rung that builds for some realistic hello, or the
	// sweep would lose points MEASUREMENTS.md §3 was derived from. period=128
	// and period=256 are refused on §3.2's own fixture and build fine on a
	// hello whose SNI sits deeper, which is why the check spans fixtures.
	ok := []string{"", "tlsfrag:pos=sniend-1", "tlsfrag:pos=snistart-20", "tlsfrag:pos=snimid|chunk:size=12",
		"tlsevery:period=128", "tlsevery:period=256", "chunk:size=12", "hostpad"}
	if got := alwaysRefusedCuts(ok); len(got) != 0 {
		t.Fatalf("guard flagged buildable rungs: %v", got)
	}
}
