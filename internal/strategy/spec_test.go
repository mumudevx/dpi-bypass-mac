package strategy

import (
	"errors"
	"strings"
	"testing"
)

func TestParseCanonicalises(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"", ""},
		{"plain", ""},
		{"  plain  ", ""},
		{"plain|plain", ""},
		{"tlsfrag:pos=snimid", "tlsfrag:pos=snimid"},
		{"tlsfrag:pos=snimid+0", "tlsfrag:pos=snimid"},
		{" tlsfrag : pos = snimid ", "tlsfrag:pos=snimid"},
		{"chunk:size=012", "chunk:size=12"},
		{"chunk:size=+12", "chunk:size=12"},

		// Typed order is irrelevant: steps run in Kind order, so the two
		// spellings are the same strategy and must serialise identically.
		{"chunk:size=12|hostcase", "hostcase|chunk:size=12"},
		{"hostcase|chunk:size=12", "hostcase|chunk:size=12"},
		{"chunk:size=12|tlsfrag:pos=snimid", "tlsfrag:pos=snimid|chunk:size=12"},
		{"chunk:size=12|hostdot|hostcase", "hostcase|hostdot|chunk:size=12"},
		{"plain|chunk:size=4", "chunk:size=4"},

		// Parameters sort by key and values equal to the declared default drop
		// out, so two operators who wrote the same thing two ways share a cache
		// entry and a probe result.
		{"oob:junk=1,pos=1", "oob:pos=1"},
		{"oob:pos=1,junk=1", "oob:pos=1"},
		{"oob:pos=1,junk=2", "oob:junk=2,pos=1"},
		{"quicfake:ttl=4,count=2", "quicfake"},
		{"quicfake:count=3,ttl=4", "quicfake:count=3"},
		{"hostpad:len=1", "hostpad"},
		{"hostpad:len=8", "hostpad:len=8"},
	} {
		s, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if s.String() != tc.want {
			t.Errorf("Parse(%q).String() = %q, want %q", tc.in, s.String(), tc.want)
		}
		// Canonicalisation is idempotent, and the canonical form re-parses to
		// itself. The prober serialises, caches and shares these strings.
		again, err := Parse(s.String())
		if err != nil {
			t.Errorf("re-parse of %q: %v", s.String(), err)
			continue
		}
		if again.String() != s.String() {
			t.Errorf("not idempotent: %q -> %q -> %q", tc.in, s.String(), again.String())
		}
	}
}

func TestParseUnknownOpNamesTheToken(t *testing.T) {
	_, err := Parse("tlsfrag:pos=snimid|frobnicate:size=3")
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.Is(err, ErrUnknownOp) {
		t.Fatalf("got %v, want ErrUnknownOp", err)
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error must name the offending token: %v", err)
	}
	// Gate 1 requires the alternatives to be listed, or the user is left
	// guessing at a vocabulary that only exists in the source.
	if !strings.Contains(err.Error(), "tlsfrag") || !strings.Contains(err.Error(), "chunk") {
		t.Errorf("error must list the registered ops: %v", err)
	}
}

func TestParseUnknownParamNamesTheToken(t *testing.T) {
	// The sni_match class of trap: a key that is accepted, stored and never
	// read. Here it is an error that names the key and lists the real ones.
	_, err := Parse("chunk:size=12,sni_match=discord.com")
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.Is(err, ErrUnknownParam) {
		t.Fatalf("got %v, want ErrUnknownParam", err)
	}
	if !strings.Contains(err.Error(), "sni_match") {
		t.Errorf("error must name the offending parameter: %v", err)
	}
	if !strings.Contains(err.Error(), "chunk") || !strings.Contains(err.Error(), "size") {
		t.Errorf("error must name the op and its real parameters: %v", err)
	}
}

func TestParseNoParametersListsNone(t *testing.T) {
	_, err := Parse("hostcase:x=1")
	if !errors.Is(err, ErrUnknownParam) {
		t.Fatalf("got %v, want ErrUnknownParam", err)
	}
	if !strings.Contains(err.Error(), "(none registered)") {
		t.Errorf("an op with no parameters must say so: %v", err)
	}
}

func TestParseMalformedSpecs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want error
	}{
		{"chunk:size=12||oob:pos=1", ErrBadSpec},
		{"|", ErrBadSpec},
		{"chunk:", ErrBadSpec},
		{"chunk:size", ErrBadSpec},
		{"chunk:size=12,", ErrBadSpec},
		{"chunk:size=12,size=4", ErrBadSpec},
		{"chunk:SIZE=12", ErrBadSpec},
		{"chunk:1size=12", ErrBadSpec},
		{"Chunk:size=12", ErrBadSpec},
		{"chunk:size=", ErrBadValue},
		{"chunk:size=abc", ErrBadValue},
		{"chunk:size=0", ErrBadValue},
		{"chunk:size=99999999", ErrBadValue},
		{"tlsfrag:pos=nowhere", ErrBadValue},
		{"tlsfrag", ErrBadValue},
		{"chunk", ErrBadValue},
		{"nosuchop", ErrUnknownOp},
		{"chunk:size=12|chunk:size=4", ErrDuplicateOp},
	} {
		_, err := Parse(tc.in)
		if err == nil {
			t.Errorf("Parse(%q) succeeded, want %v", tc.in, tc.want)
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("Parse(%q) = %v, want %v", tc.in, err, tc.want)
		}
	}
}

func TestParseBadValueNamesTheParameter(t *testing.T) {
	_, err := Parse("chunk:size=999999")
	if !errors.Is(err, ErrBadValue) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "size") || !strings.Contains(err.Error(), "chunk") {
		t.Errorf("error must name the op and the parameter: %v", err)
	}
}

func TestMustParsePanicsOnGarbage(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustParse must panic: a compiled-in spec that does not parse is a build defect")
		}
	}()
	MustParse("nosuchop")
}

func TestMustParseAcceptsAShippedSpec(t *testing.T) {
	if got := MustParse("tlsfrag:pos=snimid").String(); got != "tlsfrag:pos=snimid" {
		t.Fatalf("MustParse = %q", got)
	}
}

func TestStrategyProperties(t *testing.T) {
	plain := MustParse("")
	if !plain.IsPlain() || plain.Label() != "plain" || plain.String() != "" {
		t.Fatalf("plain: IsPlain=%v Label=%q String=%q", plain.IsPlain(), plain.Label(), plain.String())
	}
	// Rung 1 asks nothing of the transport beyond writing the stream.
	if got := plain.Caps(); got != CapStreamWrite {
		t.Errorf("plain.Caps() = %s, want %s", got, CapStreamWrite)
	}
	if got := plain.Requires(); got != 0 {
		t.Errorf("plain.Requires() = %s, want none", got)
	}
	if got := plain.Determinism(); got != DetRuleBased {
		t.Errorf("plain.Determinism() = %s: there is no constant to be wrong about", got)
	}

	frag := MustParse("tlsfrag:pos=snimid")
	if frag.IsPlain() || frag.Label() != "tlsfrag:pos=snimid" {
		t.Errorf("tlsfrag: IsPlain=%v Label=%q", frag.IsPlain(), frag.Label())
	}
	if got := frag.Determinism(); got != DetRuleBased {
		t.Errorf("tlsfrag.Determinism() = %s, want rule-based (MEASUREMENTS.md §3.3)", got)
	}
	if got := frag.Requires(); got != ReqComplete|ReqSNI {
		t.Errorf("tlsfrag.Requires() = %s", got)
	}

	// Ranking key 3 must not be fooled by a composite: one empirical constant
	// in the pipeline makes the whole result an empirical constant.
	mixed := MustParse("tlsfrag:pos=snimid|chunk:size=12")
	if got := mixed.Determinism(); got != DetEmpirical {
		t.Errorf("composite Determinism = %s, want empirical", got)
	}
	if got := mixed.Caps(); got != CapStreamWrite|CapNoDelay {
		t.Errorf("composite Caps = %s", got)
	}

	oob := MustParse("oob:pos=1")
	if got := oob.Caps(); got != CapStreamWrite|CapNoDelay|CapOOB {
		t.Errorf("oob.Caps() = %s, want the OOB bit", got)
	}
}

func TestStrategyStepOrderIsKindOrder(t *testing.T) {
	s := MustParse("chunk:size=12|tlsfrag:pos=snimid|hostcase")
	want := []string{"hostcase", "tlsfrag", "chunk"}
	if len(s.Steps) != len(want) {
		t.Fatalf("got %d steps, want %d", len(s.Steps), len(want))
	}
	for i, n := range want {
		if s.Steps[i].Name() != n {
			t.Fatalf("step %d is %q, want %q (mutate, then reframe, then schedule)", i, s.Steps[i].Name(), n)
		}
	}
}

func TestExplain(t *testing.T) {
	lines := MustParse("").Explain()
	if len(lines) != 2 || !strings.Contains(lines[1], "unmodified") {
		t.Fatalf("plain Explain = %q", lines)
	}

	lines = MustParse("tlsfrag:pos=snimid|chunk:size=12").Explain()
	if len(lines) != 3 {
		t.Fatalf("Explain = %q, want a header and two ops", lines)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"tlsfrag:pos=snimid", "reframe", "rule-based", "MEASUREMENTS.md §3.2", "chunk:size=12", "schedule"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Explain must mention %q:\n%s", want, joined)
		}
	}
}

func TestArgsAccessors(t *testing.T) {
	a := Args{"size": "12", "on": "yes", "off": "0", "pos": "snimid", "name": "x", "bad": "nope"}

	if n, err := a.Int("size", 0); err != nil || n != 12 {
		t.Errorf("Int = %d, %v", n, err)
	}
	if n, err := a.Int("absent", 7); err != nil || n != 7 {
		t.Errorf("Int default = %d, %v", n, err)
	}
	if _, err := a.Int("bad", 0); !errors.Is(err, ErrBadValue) {
		t.Errorf("Int on a non-number = %v", err)
	}
	if n, err := a.IntRange("size", 0, 1, 100); err != nil || n != 12 {
		t.Errorf("IntRange = %d, %v", n, err)
	}
	if _, err := a.IntRange("size", 0, 1, 5); !errors.Is(err, ErrBadValue) {
		t.Errorf("IntRange out of range = %v", err)
	}
	if _, err := a.IntRange("bad", 0, 1, 5); !errors.Is(err, ErrBadValue) {
		t.Errorf("IntRange on a non-number = %v", err)
	}
	if got := a.Str("name", "d"); got != "x" {
		t.Errorf("Str = %q", got)
	}
	if got := a.Str("absent", "d"); got != "d" {
		t.Errorf("Str default = %q", got)
	}
	if v, err := a.Bool("on", false); err != nil || !v {
		t.Errorf("Bool = %v, %v", v, err)
	}
	if v, err := a.Bool("off", true); err != nil || v {
		t.Errorf("Bool = %v, %v", v, err)
	}
	if v, err := a.Bool("absent", true); err != nil || !v {
		t.Errorf("Bool default = %v, %v", v, err)
	}
	if _, err := a.Bool("bad", false); !errors.Is(err, ErrBadValue) {
		t.Errorf("Bool on garbage = %v", err)
	}
	if p, err := a.Pos("pos", Pos{}); err != nil || p.Anchor != AnchorSNIMid {
		t.Errorf("Pos = %+v, %v", p, err)
	}
	def := Pos{Anchor: AnchorSNIEnd, Delta: -1}
	if p, err := a.Pos("absent", def); err != nil || p != def {
		t.Errorf("Pos default = %+v, %v", p, err)
	}
	if _, err := a.Pos("bad", Pos{}); !errors.Is(err, ErrBadValue) {
		t.Errorf("Pos on garbage = %v", err)
	}
	if got := a.Unknown("size", "on", "off", "pos", "name"); len(got) != 1 || got[0] != "bad" {
		t.Errorf("Unknown = %v, want [bad]", got)
	}
	if got := (Args{}).Unknown("size"); got != nil {
		t.Errorf("Unknown on empty args = %v", got)
	}
}

func TestCanonValueIsIdempotent(t *testing.T) {
	for _, in := range []string{"", "12", "012", "+12", "-3", "snimid+0", "sniend-1", "true", "discord.com", " 7 "} {
		once := canonValue(in)
		if twice := canonValue(once); twice != once {
			t.Errorf("canonValue(%q) = %q, canonValue again = %q", in, once, twice)
		}
	}
	if got := canonValue("012"); got != "12" {
		t.Errorf("canonValue(012) = %q", got)
	}
	if got := canonValue("snimid+0"); got != "snimid" {
		t.Errorf("canonValue(snimid+0) = %q", got)
	}
	if got := canonValue("discord.com"); got != "discord.com" {
		t.Errorf("canonValue must leave an opaque string alone, got %q", got)
	}
}
