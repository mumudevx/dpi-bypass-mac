package emit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/strategy"
)

func TestSendEmitsSegmentsInOrder(t *testing.T) {
	f := newFake()
	s := &Sender{}
	p := streamPlan("chunk:size=2", "ab", "cd", "ef")

	if err := s.Send(context.Background(), f, p); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := f.writeCount(); got != 3 {
		t.Fatalf("write count = %d, want 3 (one per segment)", got)
	}
	if got := string(f.stream()); got != "abcdef" {
		t.Fatalf("peer stream = %q, want %q", got, "abcdef")
	}
}

func TestSendRefusesAPlanTheTransportCannotEmit(t *testing.T) {
	f := newFake()
	f.caps = strategy.CapStreamWrite | strategy.CapNoDelay // no OOB

	p := streamPlan("oob:pos=1", "ab", "cd")
	p.Segments = append(p.Segments[:1],
		append([]strategy.Segment{{Kind: strategy.SegOOBByte, Data: []byte{'X'}}},
			p.Segments[1:]...)...)

	err := (&Sender{}).Send(context.Background(), f, p)
	if !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("Send err = %v, want ErrCapUnavailable", err)
	}
	// The error must name the shortfall: "desync failed" with no mechanical
	// reason is the failure mode this package exists to prevent.
	if !strings.Contains(err.Error(), "oob") {
		t.Fatalf("error does not name the missing capability: %v", err)
	}
	if f.writeCount() != 0 {
		t.Fatalf("wrote %d segments despite a missing capability", f.writeCount())
	}
}

func TestSendRestoresTTLWhenAWriteFails(t *testing.T) {
	f := newFake()
	f.failWriteAt = 2

	p := streamPlan("disorder", "ab", "cd")
	p.Segments[0].TTL = 1

	err := (&Sender{}).Send(context.Background(), f, p)
	if !errors.Is(err, errFakeWrite) {
		t.Fatalf("Send err = %v, want the transport's write error", err)
	}
	// Segment 1 carries TTL=1; segment 2 does not, so the sender restores before
	// writing it. There must be no second restore from the defer, and no leak.
	if len(f.ttlSet) != 1 || f.ttlSet[0] != 1 {
		t.Fatalf("SetTTL calls = %v, want exactly [1]", f.ttlSet)
	}
	if f.resets != 1 {
		t.Fatalf("ResetTTL calls = %d, want 1", f.resets)
	}
}

func TestSendRestoresTTLFromTheDeferWhenTheLastSegmentFails(t *testing.T) {
	f := newFake()
	f.failWriteAt = 1

	p := streamPlan("disorder", "ab")
	p.Segments[0].TTL = 1

	if err := (&Sender{}).Send(context.Background(), f, p); err == nil {
		t.Fatal("Send returned nil, want the write error")
	}
	if f.resets != 1 {
		t.Fatalf("ResetTTL calls = %d, want 1: the socket outlives the plan and "+
			"leaving TTL=1 would black-hole the relay", f.resets)
	}
}

func TestSendSurvivesAFailedTTLRestore(t *testing.T) {
	f := newFake()
	f.failWriteAt = 1
	f.failReset = true

	var logged []string
	s := &Sender{Logf: func(format string, a ...any) { logged = append(logged, format) }}

	p := streamPlan("disorder", "ab")
	p.Segments[0].TTL = 1

	if err := s.Send(context.Background(), f, p); !errors.Is(err, errFakeWrite) {
		t.Fatalf("Send err = %v, want the write error preserved", err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "restore") {
		t.Fatalf("a failed restore must be logged with a remediation, got %v", logged)
	}
}

func TestSendReportsAShortWrite(t *testing.T) {
	f := newFake()
	f.shortWrite = true

	err := (&Sender{}).Send(context.Background(), f, streamPlan("plain", "abcdef"))
	if !errors.Is(err, ErrShortWrite) {
		t.Fatalf("Send err = %v, want ErrShortWrite: a torn stream must stop the plan", err)
	}
}

// oobPlan is the shape the tr ladder's last rung emits: a head write, the
// urgent byte, then the rest.
func oobPlan() strategy.Plan {
	return strategy.Plan{
		Spec:    "oob:pos=2",
		Payload: []byte("abcd"),
		Segments: []strategy.Segment{
			{Kind: strategy.SegStream, Data: []byte("ab")},
			{Kind: strategy.SegOOBByte, Data: []byte{'X'}},
			{Kind: strategy.SegStream, Data: []byte("cd")},
		},
	}
}

// TestSendPreservesTheSyscallErrorOnTheOOBPath is the urgent-byte half of the
// promise Send's doc comment makes: "the underlying syscall error is preserved
// through %w so errors.Is on syscall.ECONNRESET / EPIPE still works at the call
// site". It was only ever exercised on the stream path, so inverting the error
// check in emitSegment's SegOOBByte arm — which turns a failed urgent write
// into a bare ErrShortWrite with the errno discarded — passed the whole suite.
// oob:pos=1 is the last rung of the tr ladder and the most destructive emitter
// (MEASUREMENTS.md §5.1, 0/20 on fragile hosts), so it is the one rung whose
// reported cause a user is most likely to read.
func TestSendPreservesTheSyscallErrorOnTheOOBPath(t *testing.T) {
	f := newFake()
	f.failOOBAt = 1

	err := (&Sender{}).Send(context.Background(), f, oobPlan())
	if err == nil {
		t.Fatal("Send returned nil for a refused urgent byte")
	}
	if !errors.Is(err, errFakeOOB) {
		t.Fatalf("Send err = %v, want the transport's urgent-write error", err)
	}
	if !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("Send err = %v; errors.Is(err, syscall.EPIPE) must still hold at the call site", err)
	}
	if errors.Is(err, ErrShortWrite) {
		t.Fatalf("a refused urgent byte was reported as a short write: %v", err)
	}
	// The plan must stop there: the segment after the urgent byte carries the
	// rest of the hello, and writing it after the desync failed would put a
	// half-desynced hello on the wire.
	if got := string(f.stream()); got != "ab" {
		t.Fatalf("stream = %q, want %q: the plan must stop at the failed segment", got, "ab")
	}
	// And the error must say which segment, in the same shape as the stream path.
	if !strings.Contains(err.Error(), "oob") {
		t.Fatalf("error does not name the segment kind: %v", err)
	}
}

// TestSendReportsAShortOOBWrite covers the other arm: the write succeeded but
// took fewer bytes, which is a torn desync rather than a wire error.
func TestSendReportsAShortOOBWrite(t *testing.T) {
	f := newFake()
	f.shortOOB = true

	p := oobPlan()
	p.Segments[1].Data = []byte{'X', 'Y'}

	err := (&Sender{}).Send(context.Background(), f, p)
	if !errors.Is(err, ErrShortWrite) {
		t.Fatalf("Send err = %v, want ErrShortWrite", err)
	}
	if errors.Is(err, errFakeOOB) {
		t.Fatalf("a short urgent write must not claim a wire error: %v", err)
	}
}

func TestSendEmitsOOBAndRawSegments(t *testing.T) {
	f := newFake()
	f.caps |= strategy.CapRawInject

	p := strategy.Plan{
		Spec:    "oob:pos=2",
		Payload: []byte("abcd"),
		Segments: []strategy.Segment{
			{Kind: strategy.SegStream, Data: []byte("ab")},
			{Kind: strategy.SegOOBByte, Data: []byte{'X'}},
			{Kind: strategy.SegFakeRaw, Data: []byte{0x45, 0x00}},
			{Kind: strategy.SegStream, Data: []byte("cd")},
		},
	}
	if err := (&Sender{}).Send(context.Background(), f, p); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := string(f.stream()); got != "abcd" {
		t.Fatalf("in-band stream = %q, want %q: junk must never join the payload", got, "abcd")
	}
	if len(f.oob) != 1 || f.oob[0][0] != 'X' {
		t.Fatalf("oob writes = %q, want one 'X'", f.oob)
	}
	if len(f.injected) != 1 {
		t.Fatalf("raw injections = %d, want 1", len(f.injected))
	}
}

func TestSendRejectsAnUnknownSegmentKind(t *testing.T) {
	f := newFake()
	p := strategy.Plan{Spec: "x", Payload: []byte("ab"),
		Segments: []strategy.Segment{{Kind: strategy.SegKind(9), Data: []byte("ab")}}}

	if err := (&Sender{}).Send(context.Background(), f, p); err == nil {
		t.Fatal("Send accepted an unknown segment kind")
	}
}

func TestSendHonoursContextCancellation(t *testing.T) {
	f := newFake()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := (&Sender{}).Send(ctx, f, streamPlan("chunk:size=2", "ab", "cd"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Send err = %v, want context.Canceled", err)
	}
	if f.writeCount() != 0 {
		t.Fatalf("wrote %d segments after cancellation", f.writeCount())
	}
}

func TestSendCancelsInsideASegmentDelay(t *testing.T) {
	f := newFake()
	ctx, cancel := context.WithCancel(context.Background())

	p := streamPlan("chunk:size=2", "ab", "cd")
	p.Segments[1].Delay = 5 * time.Second

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := (&Sender{}).Send(ctx, f, p)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Send err = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a cancelled delay took %s: the sleep is not watching the context", d)
	}
}

func TestSendAppliesASegmentDelay(t *testing.T) {
	f := newFake()
	p := streamPlan("chunk:size=2", "ab", "cd")
	p.Segments[1].Delay = 30 * time.Millisecond

	start := time.Now()
	if err := (&Sender{}).Send(context.Background(), f, p); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if d := time.Since(start); d < 25*time.Millisecond {
		t.Fatalf("plan finished in %s, want at least the 30ms segment delay", d)
	}
}

func TestSendEmptyPlanAndBrokenPlan(t *testing.T) {
	f := newFake()
	if err := (&Sender{}).Send(context.Background(), f, strategy.Plan{Spec: "plain"}); err != nil {
		t.Fatalf("an empty plan must be a no-op, got %v", err)
	}
	broken := strategy.Plan{Spec: "plain", Payload: []byte("ab")}
	if err := (&Sender{}).Send(context.Background(), f, broken); err == nil {
		t.Fatal("a plan with payload but no segments must be refused, not silently dropped")
	}
	if err := (&Sender{}).Send(context.Background(), nil, streamPlan("plain", "a")); err == nil {
		t.Fatal("Send accepted a nil transport")
	}
}

func TestSinglewritePlanNeverReachesTheGovernor(t *testing.T) {
	// The XNU small-write guard must not be able to degrade tlsfrag, the primary
	// emitter (MEASUREMENTS.md §5.3 rung 2), which is exactly one write.
	gov := newGovernor(1, 1, time.Now)
	gov.tokens = 0
	f := newFake()

	if err := (&Sender{Gov: gov}).Send(context.Background(), f, streamPlan("tlsfrag:pos=snimid", "abcdef")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if st := gov.Stats(); st.Granted != 0 || st.Coalesced != 0 {
		t.Fatalf("governor saw a one-write plan: %+v", st)
	}
}

func TestCoalesceMergesFromTheTailAndPreservesTheStream(t *testing.T) {
	// MEASUREMENTS.md §3.2 makes the FIRST boundary the load-bearing one, so a
	// governor short on tokens must give up the late splits, not the early ones.
	segs := []strategy.Segment{
		{Kind: strategy.SegStream, Data: []byte("aa")},
		{Kind: strategy.SegStream, Data: []byte("bb")},
		{Kind: strategy.SegStream, Data: []byte("cc")},
		{Kind: strategy.SegStream, Data: []byte("dd")},
	}
	got := coalesce(segs, 2)
	if len(got) != 2 {
		t.Fatalf("coalesce to 2 produced %d segments", len(got))
	}
	if string(got[0].Data) != "aa" {
		t.Fatalf("first segment = %q, want the original %q: the head must survive", got[0].Data, "aa")
	}
	if string(got[1].Data) != "bbccdd" {
		t.Fatalf("tail segment = %q, want %q", got[1].Data, "bbccdd")
	}
	var joined []byte
	for _, s := range got {
		joined = append(joined, s.Data...)
	}
	if !bytes.Equal(joined, []byte("aabbccdd")) {
		t.Fatalf("coalescing changed the stream: %q", joined)
	}
	// The input must be untouched: a Plan is a value the verdict store may hold.
	if string(segs[1].Data) != "bb" {
		t.Fatalf("coalesce mutated its input: %q", segs[1].Data)
	}
}

func TestCoalesceRefusesToCrossASemanticBoundary(t *testing.T) {
	segs := []strategy.Segment{
		{Kind: strategy.SegStream, Data: []byte("aa"), TTL: 1},
		{Kind: strategy.SegStream, Data: []byte("bb")},
		{Kind: strategy.SegOOBByte, Data: []byte{'X'}},
		{Kind: strategy.SegStream, Data: []byte("cc"), Delay: time.Millisecond},
	}
	got := coalesce(segs, 1)
	if len(got) != 4 {
		t.Fatalf("coalesce merged across a TTL change, an OOB byte or a delay: %d segments left", len(got))
	}
}

func TestCoalesceIsANoopWhenWithinBudget(t *testing.T) {
	segs := []strategy.Segment{{Kind: strategy.SegStream, Data: []byte("aa")}}
	if got := coalesce(segs, 4); len(got) != 1 {
		t.Fatalf("coalesce changed a plan already within budget")
	}
	if got := coalesce(segs, 0); len(got) != 1 {
		t.Fatalf("coalesce with max<1 must leave the plan alone")
	}
}

func TestPlanName(t *testing.T) {
	if got := planName(strategy.Plan{}); got != "plain" {
		t.Fatalf("planName of the empty spec = %q, want %q", got, "plain")
	}
	if got := planName(strategy.Plan{Spec: "chunk:size=12"}); got != "chunk:size=12" {
		t.Fatalf("planName = %q", got)
	}
}
