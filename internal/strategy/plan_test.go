package strategy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDefaultBudget(t *testing.T) {
	b := DefaultBudget()
	// DOSSIER §3 caps segments at 16, which doubles as the guard for the XNU
	// `if_sndbyte_unsent >= 0` panic that a high volume of small writes provokes.
	if b.MaxSegments != 16 {
		t.Errorf("MaxSegments = %d, want 16", b.MaxSegments)
	}
	if b.MinSegment != 1 {
		t.Errorf("MinSegment = %d, want 1", b.MinSegment)
	}
	if b.MaxTotalDelay != 250*time.Millisecond {
		t.Errorf("MaxTotalDelay = %s, want 250ms", b.MaxTotalDelay)
	}
	if b.MaxPayload != 64<<10 {
		t.Errorf("MaxPayload = %d, want 64 KiB", b.MaxPayload)
	}
	if (Budget{}).orDefault() != b {
		t.Error("a zero budget must resolve to the default rather than rejecting every plan")
	}
	if b.orDefault() != b {
		t.Error("a set budget must be used as given")
	}
}

// The XNU write-volume guard as an invariant, not a comment.
func TestPlanWithSeventeenSegmentsFailsTheDefaultBudget(t *testing.T) {
	payload := make([]byte, 17)
	segs := make([]Segment, 0, 17)
	for i := range payload {
		payload[i] = byte(i)
		segs = append(segs, Segment{Kind: SegStream, Data: payload[i : i+1]})
	}
	p := Plan{Spec: "chunk:size=1", Payload: payload, Segments: segs}
	if !bytes.Equal(p.StreamBytes(), p.Payload) {
		t.Fatal("fixture is wrong: the segments must reassemble into the payload")
	}
	err := p.Validate(DefaultBudget())
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("17 segments: %v, want ErrBudget", err)
	}
	if !strings.Contains(err.Error(), "17") || !strings.Contains(err.Error(), "16") {
		t.Errorf("the error must name both numbers: %v", err)
	}
	// Sixteen is the boundary and must pass.
	p.Segments = segs[:16]
	p.Payload = payload[:16]
	if err := p.Validate(DefaultBudget()); err != nil {
		t.Fatalf("16 segments: %v", err)
	}
}

func TestPlanValidateStreamIntegrity(t *testing.T) {
	payload := []byte("abcdefgh")
	// A bypass tool that corrupts a stream is worse than no tool, so a plan
	// whose writes do not reassemble into its payload is rejected outright.
	for name, segs := range map[string][]Segment{
		"dropped bytes":   {{Kind: SegStream, Data: payload[:4]}},
		"reordered":       {{Kind: SegStream, Data: payload[4:]}, {Kind: SegStream, Data: payload[:4]}},
		"duplicated":      {{Kind: SegStream, Data: payload}, {Kind: SegStream, Data: payload}},
		"oob counted in":  {{Kind: SegStream, Data: payload}, {Kind: SegStream, Data: []byte("!")}},
		"nothing emitted": nil,
	} {
		p := Plan{Payload: payload, Segments: segs}
		if err := p.Validate(DefaultBudget()); !errors.Is(err, ErrStreamCorrupt) {
			t.Errorf("%s: %v, want ErrStreamCorrupt", name, err)
		}
	}

	// The OOB junk byte and a raw decoy are excluded by construction, so a plan
	// carrying them still reassembles exactly.
	ok := Plan{Payload: payload, Segments: []Segment{
		{Kind: SegStream, Data: payload[:4]},
		{Kind: SegOOBByte, Data: []byte("!")},
		{Kind: SegFakeRaw, Data: []byte("fake packet")},
		{Kind: SegStream, Data: payload[4:]},
	}}
	if err := ok.Validate(DefaultBudget()); err != nil {
		t.Fatalf("out-of-band bytes must not count as stream bytes: %v", err)
	}
}

func TestPlanValidateRejects(t *testing.T) {
	payload := []byte("abcdefgh")
	for _, tc := range []struct {
		name string
		p    Plan
		bud  Budget
		want error
	}{
		{
			"payload over budget",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload}}},
			Budget{MaxSegments: 16, MinSegment: 1, MaxPayload: 4},
			ErrBudget,
		},
		{
			"segment below the minimum",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload[:0]}, {Kind: SegStream, Data: payload}}},
			Budget{MaxSegments: 16, MinSegment: 1},
			ErrBudget,
		},
		{
			"total delay over budget",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload, Delay: time.Second}}},
			DefaultBudget(),
			ErrBudget,
		},
		{
			"negative delay",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload, Delay: -time.Second}}},
			DefaultBudget(),
			ErrBadValue,
		},
		{
			"ttl out of range",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload, TTL: 300}}},
			DefaultBudget(),
			ErrBadValue,
		},
		{
			"negative ttl",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload, TTL: -1}}},
			DefaultBudget(),
			ErrBadValue,
		},
		{
			"oob segment carrying more than a byte",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload}, {Kind: SegOOBByte, Data: []byte("ab")}}},
			DefaultBudget(),
			ErrBadValue,
		},
		{
			"empty raw packet",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegStream, Data: payload}, {Kind: SegFakeRaw}}},
			DefaultBudget(),
			ErrBadValue,
		},
		{
			"unknown segment kind",
			Plan{Payload: payload, Segments: []Segment{{Kind: SegKind(9), Data: payload}}},
			DefaultBudget(),
			ErrBadValue,
		},
	} {
		if err := tc.p.Validate(tc.bud); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestPlanCaps(t *testing.T) {
	payload := []byte("abcdefgh")
	for _, tc := range []struct {
		name string
		segs []Segment
		want Cap
	}{
		{"one write", []Segment{{Kind: SegStream, Data: payload}}, CapStreamWrite},
		{
			"two writes need Nagle off",
			[]Segment{{Kind: SegStream, Data: payload[:4]}, {Kind: SegStream, Data: payload[4:]}},
			CapStreamWrite | CapNoDelay,
		},
		{
			"per-segment ttl",
			[]Segment{{Kind: SegStream, Data: payload[:4], TTL: 1}, {Kind: SegStream, Data: payload[4:]}},
			CapStreamWrite | CapNoDelay | CapSockTTL,
		},
		{
			"oob byte",
			[]Segment{{Kind: SegStream, Data: payload}, {Kind: SegOOBByte, Data: []byte("!")}},
			CapStreamWrite | CapNoDelay | CapOOB,
		},
		{
			"raw decoy",
			[]Segment{{Kind: SegStream, Data: payload}, {Kind: SegFakeRaw, Data: []byte("p")}},
			CapStreamWrite | CapNoDelay | CapRawInject,
		},
	} {
		p := Plan{Payload: payload, Segments: tc.segs}
		if got := p.Caps(); got != tc.want {
			t.Errorf("%s: Caps = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestPlanAccessors(t *testing.T) {
	payload := []byte("abcdefgh")
	p := Plan{
		Spec:    "chunk:size=4",
		Payload: payload,
		Segments: []Segment{
			{Kind: SegStream, Data: payload[:4], TTL: 1, Note: "head"},
			{Kind: SegOOBByte, Data: []byte("!")},
			{Kind: SegStream, Data: payload[4:], Delay: 5 * time.Millisecond},
		},
		Notes: []string{"a note"},
	}
	if p.WriteCount() != 3 {
		t.Errorf("WriteCount = %d", p.WriteCount())
	}
	if p.TotalDelay() != 5*time.Millisecond {
		t.Errorf("TotalDelay = %s", p.TotalDelay())
	}
	if !bytes.Equal(p.StreamBytes(), payload) {
		t.Errorf("StreamBytes = %q", p.StreamBytes())
	}
	if p.String() != "chunk:size=4" {
		t.Errorf("String = %q", p.String())
	}

	d := p.Describe()
	if len(d) != 5 {
		t.Fatalf("Describe = %q", d)
	}
	joined := strings.Join(d, "\n")
	for _, want := range []string{"chunk:size=4", "ttl=1", "5ms", "head", "a note", "oob"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Describe must mention %q:\n%s", want, joined)
		}
	}
	// A plan carries a hostname; the description must never print its bytes.
	if strings.Contains(joined, string(payload)) {
		t.Errorf("Describe leaked payload bytes:\n%s", joined)
	}
	if !strings.Contains(p.Summary(), "chunk:size=4") {
		t.Errorf("Summary = %q", p.Summary())
	}

	plain := Plan{Segments: []Segment{}}
	if !strings.Contains(plain.Describe()[0], "plain") {
		t.Errorf("an empty spec must describe itself as plain: %q", plain.Describe())
	}
	if plain.StreamBytes() != nil {
		t.Error("StreamBytes on an empty plan must be nil")
	}
}
