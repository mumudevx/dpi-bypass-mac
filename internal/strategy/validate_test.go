package strategy

import (
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// Gate 2: at most one op may own the record layer, and at most one may own the
// write schedule. Two of either is not a composition, it is a contradiction.
func TestCompositionRejectsTwoReframers(t *testing.T) {
	_, err := Parse("tlsfrag:pos=snimid|tlsevery:period=64")
	if !errors.Is(err, ErrOneReframe) {
		t.Fatalf("got %v, want ErrOneReframe", err)
	}
	if !strings.Contains(err.Error(), "tlsfrag") || !strings.Contains(err.Error(), "tlsevery") {
		t.Errorf("the error must name both ops: %v", err)
	}
}

func TestCompositionRejectsTwoSchedulers(t *testing.T) {
	_, err := Parse("chunk:size=12|split:pos=1")
	if !errors.Is(err, ErrOneSchedule) {
		t.Fatalf("got %v, want ErrOneSchedule", err)
	}
	if !strings.Contains(err.Error(), "chunk") || !strings.Contains(err.Error(), "split") {
		t.Errorf("the error must name both ops: %v", err)
	}
}

// disorder and oob are mutually exclusive, and the refusal must carry the
// citation — an operator who reads "rejected" without a reason will try to
// re-enable it.
func TestCompositionRejectsDisorderWithOOB(t *testing.T) {
	for _, spec := range []string{"disorder:pos=1|oob:pos=1", "oob:pos=1|disorder:pos=1"} {
		_, err := Parse(spec)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded", spec)
		}
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("Parse(%q) = %v, want ErrIncompatible", spec, err)
		}
	}

	// Checked directly so the citation is asserted regardless of which rule the
	// parser reaches first.
	d, _ := Default().lookup("disorder")
	o, _ := Default().lookup("oob")
	err := checkComposition([]Op{d, o})
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("got %v, want ErrIncompatible", err)
	}
	msg := err.Error()
	for _, want := range []string{"disorder", "oob", "darwin", "zapret", "URG", "--disoob", "0/8", "8/8"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must cite %q: %s", want, msg)
		}
	}
}

// An op that can never work is registered rather than absent, so asking for it
// returns a mechanical reason instead of "unknown op".
func TestRejectedOpGivesACitedError(t *testing.T) {
	_, err := Parse("seqovl:pos=4")
	if !errors.Is(err, ErrOpRejected) {
		t.Fatalf("got %v, want ErrOpRejected", err)
	}
	msg := err.Error()
	for _, want := range []string{"seqovl", "snd_nxt", "tcp_connection_info", "CapRawSeq"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must cite %q: %s", want, msg)
		}
	}
	if errors.Is(err, ErrUnknownOp) {
		t.Error("a rejected op must not read as an unknown one")
	}
}

func TestCheckAgainstCapabilities(t *testing.T) {
	_, m := measuredFixture()
	s := MustParse("oob:pos=1")

	// A profile naming a strategy the transport cannot satisfy must refuse to
	// load with the shortfall named, not quietly emit something weaker.
	err := s.CheckAgainst(CapStreamWrite|CapNoDelay, m)
	if !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("got %v, want ErrCapUnavailable", err)
	}
	if !strings.Contains(err.Error(), "oob") {
		t.Errorf("the error must name the missing capability: %v", err)
	}
	if err := s.CheckAgainst(allCaps, m); err != nil {
		t.Fatalf("a transport with every capability: %v", err)
	}
	if err := MustParse("").CheckAgainst(CapStreamWrite, m); err != nil {
		t.Fatalf("plain must be satisfiable by any transport: %v", err)
	}
}

func TestCheckAgainstMessageRequirements(t *testing.T) {
	payload, m := measuredFixture()
	frag := MustParse("tlsfrag:pos=snimid")

	if err := frag.CheckAgainst(allCaps, m); err != nil {
		t.Fatalf("a complete hello with an SNI: %v", err)
	}

	incomplete := m
	incomplete.Complete = false
	incomplete.Truncated = true
	if err := frag.CheckAgainst(allCaps, incomplete); !errors.Is(err, ErrNeedComplete) {
		t.Fatalf("got %v, want ErrNeedComplete", err)
	}

	noSNI := m
	noSNI.SNIStart, noSNI.SNIEnd = -1, -1
	if err := frag.CheckAgainst(allCaps, noSNI); !errors.Is(err, ErrNeedSNI) {
		t.Fatalf("got %v, want ErrNeedSNI", err)
	}

	// A port-80 mutator against a TLS message has nothing to mangle.
	if err := MustParse("hostcase").CheckAgainst(allCaps, m); !errors.Is(err, ErrNeedHost) {
		t.Fatalf("got %v, want ErrNeedHost", err)
	}
	_ = payload
}

func TestStrategyBuildEndToEnd(t *testing.T) {
	payload, m := measuredFixture()

	for _, tc := range []struct {
		spec       string
		writes     int
		payloadLen int
	}{
		{"", 1, len(payload)},
		{"tlsfrag:pos=snimid", 1, len(payload) + 5},    // two records, ONE write
		{"tlsevery:period=64", 1, len(payload) + 23*5}, // 1497/64 = 23 extra records
		{"chunk:size=120", 13, len(payload)},           // 1502/120 rounded up
		{"tlsfrag:pos=snimid|chunk:size=200", 8, len(payload) + 5},
	} {
		s, err := Parse(tc.spec)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.spec, err)
		}
		p, err := s.Build(payload, m, allCaps, DefaultBudget())
		if err != nil {
			t.Fatalf("Build(%q): %v", tc.spec, err)
		}
		if p.WriteCount() != tc.writes {
			t.Errorf("%q: WriteCount = %d, want %d", tc.spec, p.WriteCount(), tc.writes)
		}
		if len(p.Payload) != tc.payloadLen {
			t.Errorf("%q: payload = %d bytes, want %d", tc.spec, len(p.Payload), tc.payloadLen)
		}
		if p.Spec != s.String() {
			t.Errorf("%q: plan spec = %q, want the canonical %q", tc.spec, p.Spec, s.String())
		}
		// The invariant, on every plan.
		if err := p.Validate(DefaultBudget()); err != nil {
			t.Errorf("%q: %v", tc.spec, err)
		}
	}
}

// Build must not mutate the caller's buffer: the ladder re-reads the same
// first message on every rung, and a mutator that scribbled on it would make
// rung 3 a different experiment from rung 2.
func TestBuildDoesNotMutateTheCallersPayload(t *testing.T) {
	payload, m := httpFixture("example.com")
	before := append([]byte(nil), payload...)
	s := MustParse("hostcase|hostdot")
	if _, err := s.Build(payload, m, allCaps, DefaultBudget()); err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(before) {
		t.Fatalf("Build mutated the caller's payload:\n got %q\nwant %q", payload, before)
	}
}

func TestBuildAppliesMutatorsThenReframers(t *testing.T) {
	payload, m := httpFixture("discord.com")
	s := MustParse("chunk:size=8|hostcase")
	if s.String() != "hostcase|chunk:size=8" {
		t.Fatalf("canonical form = %q", s.String())
	}
	p, err := s.Build(payload, m, allCaps, DefaultBudget())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p.Payload), "DISCORD.COM") {
		t.Fatalf("the mutator did not run before the schedule: %q", p.Payload)
	}
	if p.WriteCount() < 2 {
		t.Fatalf("the scheduler did not run: %d writes", p.WriteCount())
	}
}

func TestBuildSurfacesAnOpError(t *testing.T) {
	payload, m := measuredFixture()
	s := MustParse("tlsfrag:pos=sniend")
	_, err := s.Build(payload, m, allCaps, DefaultBudget())
	if !errors.Is(err, ErrCutAfterSNI) {
		t.Fatalf("got %v, want ErrCutAfterSNI", err)
	}
	// The message must locate the failure: which spec, which op.
	if !strings.Contains(err.Error(), "tlsfrag") {
		t.Errorf("error must name the op: %v", err)
	}
}

func TestBuildWithStrictBuilder(t *testing.T) {
	payload, m := tlsFixture(40, 10, 20)
	s := MustParse("split:pos=9999")

	lenient := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
	if _, err := s.BuildWith(lenient); err != nil {
		t.Fatalf("a lenient builder degrades to one write: %v", err)
	}

	strict := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps, Strict: true}
	if _, err := s.BuildWith(strict); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("got %v, want ErrDowngrade", err)
	}
}

func TestBuildRefusesBeforeTouchingBytes(t *testing.T) {
	payload, m := measuredFixture()
	// Gate 3 fires before any op runs, so a transport without OOB never sees a
	// half-applied plan.
	if _, err := MustParse("oob:pos=1").Build(payload, m, CapStreamWrite|CapNoDelay, DefaultBudget()); !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestCheckCompositionAllowsTheShippedCombinations(t *testing.T) {
	for _, spec := range []string{
		"tlsfrag:pos=snimid|chunk:size=12",
		"hostcase|hostdot|chunk:size=12",
		"tlsfrag:pos=snimid|quicfake",
		"hostcase|hostdot|hostpad:len=4|tlsfrag:pos=snimid|chunk:size=12|quicfake",
	} {
		if _, err := Parse(spec); err != nil {
			t.Errorf("Parse(%q): %v", spec, err)
		}
	}
}

func TestRequiresIncludesCompleteForEveryReframer(t *testing.T) {
	// tlsevery does not declare ReqComplete in its doc; the Kind implies it,
	// because reframing a prefix is exactly the silent degradation
	// MEASUREMENTS.md §3.5 records.
	s := MustParse("tlsevery:period=64")
	if s.Requires()&ReqComplete == 0 {
		t.Fatal("a reframing op must require a complete first message")
	}
	m := tlsmsg.Meta{Proto: tlsmsg.ProtoTLS, SNIStart: -1, SNIEnd: -1, HostStart: -1, HostEnd: -1}
	if err := s.CheckAgainst(allCaps, m); !errors.Is(err, ErrNeedComplete) {
		t.Fatalf("got %v", err)
	}
}
