package strategy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// TestReframeEnforcesTheMeasuredRule is the centrepiece of this package. It
// drives the reframer at every cut position in MEASUREMENTS.md §3.2 — 66
// shuffled trials against discord.com and discord.gg with body=1497 and the SNI
// at [112,122) — and asserts the validator agrees with the measurement.
//
// This asserts our predicate against the recorded data, so it cannot break
// because the network changed, only because the code regressed. MEASUREMENTS.md
// §3.5 records that the previous implementation "never verified the cut landed
// before sniEnd".
func TestReframeEnforcesTheMeasuredRule(t *testing.T) {
	const (
		sniStart = 112
		sniEnd   = 122
	)
	for _, tc := range []struct {
		name string
		cut  int
		pass bool // as measured: 3/3 through, or 0/3 blocked
	}{
		{"sniStart-20", sniStart - 20, true},
		{"sniStart-1", sniStart - 1, true},
		{"sniStart", sniStart, true},
		{"sniStart+1", sniStart + 1, true},
		{"sniMid", sniStart + (sniEnd-sniStart)/2, true},
		{"sniEnd-1", sniEnd - 1, true},
		{"sniEnd", sniEnd, false},
		{"sniEnd+1", sniEnd + 1, false},
		{"sniEnd+20", sniEnd + 20, false},
		{"sniEnd+200", sniEnd + 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, m := measuredFixture()
			b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
			err := b.ReframeFirstRecord([]int{tc.cut})
			if tc.pass {
				if err != nil {
					t.Fatalf("cut %d measured 3/3 through, got %v", tc.cut, err)
				}
				checkTwoRecords(t, b.Payload, payload, tc.cut)
				return
			}
			if !errors.Is(err, ErrCutAfterSNI) {
				t.Fatalf("cut %d measured 0/3 blocked, want ErrCutAfterSNI, got %v", tc.cut, err)
			}
			if !strings.Contains(err.Error(), "sniEnd") {
				t.Errorf("the refusal must explain itself: %v", err)
			}
		})
	}
}

// checkTwoRecords asserts the reframed payload is two structurally valid TLS
// records carrying consecutive halves of the original body, in one byte string.
// MEASUREMENTS.md §3.1: tlsrec2-1seg — two records in ONE TCP segment — passes
// 3/3, so the emitter must not need a second write.
func checkTwoRecords(t *testing.T, got, orig []byte, cut int) {
	t.Helper()
	origBody := orig[5:]
	if len(got) != len(orig)+5 {
		t.Fatalf("reframed payload is %d bytes, want %d (one extra 5-byte header)", len(got), len(orig)+5)
	}
	h1, ok := tlsmsg.ParseHeader(got)
	if !ok || h1.Type != 0x16 || h1.Length != cut {
		t.Fatalf("record 1 header = %+v, want type 0x16 length %d", h1, cut)
	}
	if !bytes.Equal(got[5:5+cut], origBody[:cut]) {
		t.Error("record 1 body does not match the original bytes")
	}
	h2, ok := tlsmsg.ParseHeader(got[5+cut:])
	if !ok || h2.Type != 0x16 || h2.Length != len(origBody)-cut {
		t.Fatalf("record 2 header = %+v, want length %d", h2, len(origBody)-cut)
	}
	if !bytes.Equal(got[5+cut+5:], origBody[cut:]) {
		t.Error("record 2 body does not match the original bytes")
	}
	if h1.Version != h2.Version {
		t.Error("both records must reuse the original record version")
	}
}

// TestTLSEveryFirstRecordLimit is the same predicate seen from the periodic
// reframer, and it explains four more of MEASUREMENTS.md §3's data points:
// tlsrec-every-16 and -every-64 pass (first record ends at 16 and 64, both
// <= sniEnd-1 = 121) while tlsrec-every-256 fails (256 > 121).
func TestTLSEveryFirstRecordLimit(t *testing.T) {
	for _, tc := range []struct {
		period int
		pass   bool
	}{{16, true}, {64, true}, {128, false}, {256, false}} {
		payload, m := measuredFixture()
		b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
		var cuts []int
		for c := tc.period; c < m.BodyLen; c += tc.period {
			cuts = append(cuts, c)
		}
		err := b.ReframeFirstRecord(cuts)
		switch {
		case tc.pass && err != nil:
			t.Errorf("period %d: %v", tc.period, err)
		case !tc.pass && !errors.Is(err, ErrCutAfterSNI):
			t.Errorf("period %d: got %v, want ErrCutAfterSNI (first record ends at %d > 121)", tc.period, err, tc.period)
		}
	}
}

// A hello with no SNI has no rule to break: MaxFirstRecordEnd reports not-ok
// and the reframer must not invent a limit.
func TestReframeWithoutSNIIsAllowed(t *testing.T) {
	payload, m := tlsFixture(200, -1, -1)
	m.ServerName = ""
	b := &Builder{Payload: payload, Meta: m, Caps: allCaps}
	if err := b.ReframeFirstRecord([]int{150}); err != nil {
		t.Fatalf("reframing a hello with no SNI: %v", err)
	}
}

func TestReframeRejects(t *testing.T) {
	newB := func() *Builder {
		payload, m := measuredFixture()
		return &Builder{Payload: payload, Meta: m, Caps: allCaps}
	}

	t.Run("no cuts", func(t *testing.T) {
		if err := newB().ReframeFirstRecord(nil); !errors.Is(err, ErrBadValue) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unsorted cuts", func(t *testing.T) {
		if err := newB().ReframeFirstRecord([]int{20, 10}); !errors.Is(err, ErrBadValue) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cut out of range", func(t *testing.T) {
		// Delegated to tlsmsg.SplitRecord, which owns the record's own bounds.
		if err := newB().ReframeFirstRecord([]int{0}); err == nil {
			t.Fatal("a cut at 0 must be refused")
		}
	})
	t.Run("twice", func(t *testing.T) {
		b := newB()
		if err := b.ReframeFirstRecord([]int{20}); err != nil {
			t.Fatal(err)
		}
		if err := b.ReframeFirstRecord([]int{10}); !errors.Is(err, ErrOneReframe) {
			t.Fatalf("got %v, want ErrOneReframe", err)
		}
	})
	t.Run("after the schedule", func(t *testing.T) {
		b := newB()
		if err := b.SplitAt(100); err != nil {
			t.Fatal(err)
		}
		if err := b.ReframeFirstRecord([]int{20}); !errors.Is(err, ErrOneSchedule) {
			t.Fatalf("got %v, want ErrOneSchedule", err)
		}
	})
	t.Run("not TLS", func(t *testing.T) {
		payload, m := httpFixture("example.com")
		b := &Builder{Payload: payload, Meta: m, Caps: allCaps}
		if err := b.ReframeFirstRecord([]int{4}); !errors.Is(err, ErrNeedComplete) {
			t.Fatalf("got %v, want ErrNeedComplete", err)
		}
	})
	t.Run("incomplete", func(t *testing.T) {
		// The defect MEASUREMENTS.md §3.5 names: planning a record split against
		// a prefix degrades it into a one-byte TCP split, measured 0/5.
		payload, m := measuredFixture()
		m.Complete = false
		b := &Builder{Payload: payload, Meta: m, Caps: allCaps}
		if err := b.ReframeFirstRecord([]int{20}); !errors.Is(err, ErrNeedComplete) {
			t.Fatalf("got %v, want ErrNeedComplete", err)
		}
	})
	t.Run("payload shorter than the declared record", func(t *testing.T) {
		payload, m := measuredFixture()
		b := &Builder{Payload: payload[:100], Meta: m, Caps: allCaps}
		if err := b.ReframeFirstRecord([]int{20}); !errors.Is(err, ErrNeedComplete) {
			t.Fatalf("got %v, want ErrNeedComplete", err)
		}
	})
}

// The reframed record must still be a record a TLS stack accepts, checked
// against a genuine ClientHello rather than a synthetic Meta, so the two
// coordinate systems (record-body vs payload-absolute) are proved to agree.
func TestReframeAgainstARealClientHello(t *testing.T) {
	hello := realHello("discord.com")
	m := tlsmsg.Parse(hello, 443)
	if !m.Complete || !m.HasSNI() || m.ServerName != "discord.com" {
		t.Fatalf("fixture did not parse: %+v", m)
	}
	limit, ok := m.MaxFirstRecordEnd()
	if !ok {
		t.Fatal("MaxFirstRecordEnd not ok")
	}

	b := &Builder{Payload: append([]byte(nil), hello...), Meta: m, Caps: allCaps}
	mid := m.SNIStart + (m.SNIEnd-m.SNIStart)/2
	if err := b.ReframeFirstRecord([]int{mid}); err != nil {
		t.Fatalf("snimid cut at %d (limit %d): %v", mid, limit, err)
	}
	checkTwoRecords(t, b.Payload, hello, mid)

	// The reframed hostname must genuinely no longer be complete in record 1 —
	// that is the mechanism, not a side effect.
	rec1 := b.Payload[:5+mid]
	if bytes.Contains(rec1, []byte("discord.com")) {
		t.Error("the hostname is still complete inside the first record")
	}

	b2 := &Builder{Payload: append([]byte(nil), hello...), Meta: m, Caps: allCaps}
	if err := b2.ReframeFirstRecord([]int{m.SNIEnd}); !errors.Is(err, ErrCutAfterSNI) {
		t.Fatalf("a cut at sniEnd on a real hello: %v", err)
	}
}

func TestSplitAt(t *testing.T) {
	payload, m := tlsFixture(60, 20, 30)
	b := &Builder{Payload: payload, Meta: m, Caps: allCaps}
	if err := b.SplitAt(10, 20, 30); err != nil {
		t.Fatal(err)
	}
	if len(b.Segs) != 4 {
		t.Fatalf("got %d segments, want 4", len(b.Segs))
	}
	p, err := b.Build("test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.StreamBytes(), payload) {
		t.Fatal("splitting must not change a single byte of the stream")
	}
}

func TestSplitAtDowngradesOutOfRangeOffsets(t *testing.T) {
	payload, m := tlsFixture(60, 20, 30)

	b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
	if err := b.SplitAt(10, 10, 5, 1000, 0, -3, 20); err != nil {
		t.Fatalf("a lenient builder must drop the bad offsets: %v", err)
	}
	if len(b.Segs) != 3 {
		t.Fatalf("got %d segments, want 3 (offsets 10 and 20 survive)", len(b.Segs))
	}
	if len(b.Notes()) == 0 {
		t.Error("every downgrade must leave a note the operator can read back")
	}

	// The prober must never score a plan it did not actually emit.
	strict := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps, Strict: true}
	if err := strict.SplitAt(10, 1000); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("strict builder: %v, want ErrDowngrade", err)
	}
}

func TestSplitAtNoUsableOffsets(t *testing.T) {
	payload, m := tlsFixture(20, -1, -1)

	b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
	if err := b.SplitAt(9999); err != nil {
		t.Fatal(err)
	}
	if len(b.Segs) != 1 || len(b.Segs[0].Data) != len(payload) {
		t.Fatalf("want one whole-payload segment, got %d", len(b.Segs))
	}

	strict := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps, Strict: true}
	if err := strict.SplitAt(9999); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("got %v", err)
	}
}

func TestSplitAtRejects(t *testing.T) {
	payload, m := tlsFixture(60, 20, 30)

	empty := &Builder{Payload: nil, Meta: m, Caps: allCaps}
	if err := empty.SplitAt(1); !errors.Is(err, ErrBadValue) {
		t.Errorf("splitting an empty payload: %v", err)
	}

	twice := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
	if err := twice.SplitAt(10); err != nil {
		t.Fatal(err)
	}
	if err := twice.SplitAt(20); !errors.Is(err, ErrOneSchedule) {
		t.Errorf("a second schedule: %v, want ErrOneSchedule", err)
	}

	// The XNU small-write guard, applied before 4000 segments are allocated
	// rather than after.
	big, bigMeta := tlsFixture(4000, -1, -1)
	b := &Builder{Payload: big, Meta: bigMeta, Caps: allCaps}
	offs := make([]int, 0, 100)
	for i := 1; i <= 100; i++ {
		offs = append(offs, i)
	}
	if err := b.SplitAt(offs...); !errors.Is(err, ErrBudget) {
		t.Errorf("101 writes: %v, want ErrBudget", err)
	}
}

func TestSetSegTTL(t *testing.T) {
	payload, m := tlsFixture(60, 20, 30)
	mk := func(caps Cap) *Builder {
		b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: caps}
		if err := b.SplitAt(10); err != nil {
			t.Fatal(err)
		}
		return b
	}

	b := mk(allCaps)
	if err := b.SetSegTTL(0, 1); err != nil {
		t.Fatal(err)
	}
	if b.Segs[0].TTL != 1 {
		t.Fatalf("TTL = %d", b.Segs[0].TTL)
	}
	if err := b.SetSegTTL(5, 1); !errors.Is(err, ErrBadValue) {
		t.Errorf("out-of-range segment index: %v", err)
	}
	for _, ttl := range []int{0, -1, 256} {
		if err := b.SetSegTTL(0, ttl); !errors.Is(err, ErrBadValue) {
			t.Errorf("ttl %d: %v", ttl, err)
		}
	}

	// A missing capability is never a downgrade. Emitting the segment at the
	// default TTL is not a weaker disorder, it is a different strategy wearing
	// disorder's name — and it would be scored under that name.
	noTTL := mk(CapStreamWrite | CapNoDelay)
	if err := noTTL.SetSegTTL(0, 1); !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("got %v, want ErrCapUnavailable", err)
	}
}

func TestMarkOOB(t *testing.T) {
	payload, m := tlsFixture(60, 20, 30)
	b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
	if err := b.SplitAt(10, 20); err != nil {
		t.Fatal(err)
	}
	if err := b.MarkOOB(0, 'x'); err != nil {
		t.Fatal(err)
	}
	if len(b.Segs) != 4 {
		t.Fatalf("got %d segments, want 4", len(b.Segs))
	}
	if b.Segs[1].Kind != SegOOBByte || b.Segs[1].Data[0] != 'x' {
		t.Fatalf("segment 1 = %+v, want the junk byte right after segment 0", b.Segs[1])
	}
	if b.Segs[2].Kind != SegStream || !bytes.Equal(b.Segs[2].Data, payload[10:20]) {
		t.Fatal("the following stream segment must be intact and in order")
	}
	// The junk byte is out of band, so it must not appear in the stream the
	// peer's TCP reassembles.
	p, err := b.Build("oob")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.StreamBytes(), payload) {
		t.Fatal("the OOB byte leaked into the stream")
	}

	if err := b.MarkOOB(99, 'x'); !errors.Is(err, ErrBadValue) {
		t.Errorf("out-of-range index: %v", err)
	}
	noOOB := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: CapStreamWrite}
	if err := noOOB.SplitAt(10); err != nil {
		t.Fatal(err)
	}
	if err := noOOB.MarkOOB(0, 'x'); !errors.Is(err, ErrCapUnavailable) {
		t.Errorf("got %v, want ErrCapUnavailable", err)
	}
}

func TestReparse(t *testing.T) {
	payload, m := httpFixture("example.com")
	b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
	// Grow the payload the way a length-changing mutator does.
	out := append([]byte(nil), b.Payload[:m.HostEnd]...)
	out = append(out, '.')
	out = append(out, b.Payload[m.HostEnd:]...)
	b.Payload = out
	b.Reparse()
	if b.Meta.ServerName != "example.com." {
		t.Fatalf("reparse gave ServerName %q", b.Meta.ServerName)
	}
	if b.Meta.HostEnd != m.HostEnd+1 {
		t.Fatalf("HostEnd = %d, want %d", b.Meta.HostEnd, m.HostEnd+1)
	}
}

func TestReparsePreservesTruncatedAndDropsStaleSegments(t *testing.T) {
	payload, m := tlsFixture(60, 20, 30)
	m.Truncated = true
	b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
	if err := b.SplitAt(10); err != nil {
		t.Fatal(err)
	}
	b.Reparse()
	if !b.Meta.Truncated {
		t.Error("only the reader knows why it stopped; Truncated must survive a reparse")
	}
	if len(b.Segs) != 0 {
		t.Error("segments computed against the pre-mutation payload must be discarded")
	}
	if len(b.Notes()) == 0 {
		t.Error("discarding segments must be visible in the notes")
	}
}

func TestBuildDefaults(t *testing.T) {
	payload, m := tlsFixture(60, 20, 30)

	// No schedule means one write, which is the plain strategy and also the
	// tlsfrag strategy: MEASUREMENTS.md §3.1 measures two records in one TCP
	// segment passing 3/3.
	b := &Builder{Payload: payload, Meta: m}
	p, err := b.Build("")
	if err != nil {
		t.Fatal(err)
	}
	if p.WriteCount() != 1 {
		t.Fatalf("WriteCount = %d, want 1", p.WriteCount())
	}
	if p.Spec != "" || p.String() != "" {
		t.Fatalf("Spec = %q", p.Spec)
	}

	// An empty payload produces no writes rather than an invalid zero-length
	// segment.
	empty := &Builder{}
	p, err = empty.Build("")
	if err != nil {
		t.Fatal(err)
	}
	if p.WriteCount() != 0 {
		t.Fatalf("WriteCount = %d, want 0", p.WriteCount())
	}
}

func TestBuildRejectsAnOverBudgetPlan(t *testing.T) {
	payload, m := tlsFixture(200, -1, -1)
	b := &Builder{Payload: payload, Meta: m, Caps: allCaps, Budget: Budget{MaxSegments: 2, MinSegment: 1}}
	if err := b.SplitAt(10, 20); err == nil {
		t.Fatal("SplitAt must apply the budget before it allocates")
	} else if !errors.Is(err, ErrBudget) {
		t.Fatalf("got %v", err)
	}

	// And the same gate again at Build, for a schedule assembled by hand.
	b2 := &Builder{Payload: payload, Meta: m, Caps: allCaps, Budget: Budget{MaxSegments: 1, MinSegment: 1}}
	b2.Segs = []Segment{{Kind: SegStream, Data: payload[:100]}, {Kind: SegStream, Data: payload[100:]}}
	if _, err := b2.Build("x"); !errors.Is(err, ErrBudget) {
		t.Fatalf("got %v", err)
	}
}

func TestBuilderReframedFlag(t *testing.T) {
	payload, m := measuredFixture()
	b := &Builder{Payload: payload, Meta: m, Caps: allCaps}
	if b.Reframed() {
		t.Fatal("a fresh builder has not reframed anything")
	}
	if err := b.ReframeFirstRecord([]int{20}); err != nil {
		t.Fatal(err)
	}
	if !b.Reframed() {
		t.Fatal("Reframed must report the rewrite")
	}
	// Meta still describes the pre-reframe payload, which is the coordinate
	// system the operator's anchors were written in.
	if b.Meta.BodyLen != 1497 {
		t.Fatalf("Meta.BodyLen = %d, want the pre-reframe 1497", b.Meta.BodyLen)
	}
}

func TestBuilderNote(t *testing.T) {
	b := &Builder{}
	b.Note("hello %d", 42)
	if got := b.Notes(); len(got) != 1 || got[0] != "hello 42" {
		t.Fatalf("Notes = %v", got)
	}
}

// A reframe must leave the record layer parseable by tlsmsg's own reader, at
// every cut the rule allows.
func TestReframeOutputReparsesCleanly(t *testing.T) {
	payload, m := measuredFixture()
	for cut := 1; cut <= 121; cut += 20 {
		b := &Builder{Payload: append([]byte(nil), payload...), Meta: m, Caps: allCaps}
		if err := b.ReframeFirstRecord([]int{cut}); err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		got := tlsmsg.Parse(b.Payload, 443)
		if got.Proto != tlsmsg.ProtoTLS {
			t.Fatalf("cut %d: reframed payload no longer parses as TLS", cut)
		}
		if got.BodyLen != cut {
			t.Fatalf("cut %d: first record body is %d bytes", cut, got.BodyLen)
		}
		if binary.BigEndian.Uint16(b.Payload[3:5]) != uint16(cut) {
			t.Fatalf("cut %d: record length field is wrong", cut)
		}
	}
}

func TestBuildWithNilBuilder(t *testing.T) {
	if _, err := MustParse("").BuildWith(nil); !errors.Is(err, ErrBadValue) {
		t.Fatalf("got %v", err)
	}
}

func TestLabelHelper(t *testing.T) {
	if got := label(""); got != "plain" {
		t.Errorf("label(\"\") = %q", got)
	}
	if got := label("chunk:size=4"); got != "chunk:size=4" {
		t.Errorf("label = %q", got)
	}
}
