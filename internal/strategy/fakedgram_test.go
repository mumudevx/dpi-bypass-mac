package strategy

import (
	"bytes"
	"errors"
	"testing"
)

// The decoy-datagram segment kind, added by amendment A7's resolution.
//
// Three properties make it a kind of its own rather than a reuse of an existing
// one, and each is asserted here because each was a real defect before it
// existed: it is NOT part of the payload (SegStream would trip
// ErrStreamCorrupt), it needs only a datagram socket (SegFakeRaw derives
// CapRawInject, which nothing in this build grants, so quicfake validated
// against no transport at all), and an empty decoy is refused.

func decoyPlan() Plan {
	real := []byte("REAL")
	return Plan{
		Spec:    "quicfake",
		Payload: real,
		Segments: []Segment{
			{Kind: SegFakeDatagram, Data: []byte("DECOY"), TTL: 4},
			{Kind: SegStream, Data: real},
		},
	}
}

func TestFakeDatagramIsNotPayload(t *testing.T) {
	p := decoyPlan()
	if got := p.StreamBytes(); !bytes.Equal(got, p.Payload) {
		t.Fatalf("StreamBytes = %q, want the payload %q: a decoy leaked into the stream", got, p.Payload)
	}
	if err := p.Validate(DefaultBudget()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestFakeDatagramDerivesCapDatagram(t *testing.T) {
	got := decoyPlan().Caps()
	for _, want := range []Cap{CapDatagram, CapSockTTL, CapNoDelay, CapStreamWrite} {
		if !got.Has(want) {
			t.Errorf("Caps = %s, missing %s", got, want)
		}
	}
	if got.Has(CapRawInject) {
		t.Errorf("Caps = %s: a decoy datagram is an ordinary write, not a raw injection", got)
	}
	if SegFakeDatagram.String() != "fakedgram" {
		t.Errorf("SegFakeDatagram.String() = %q", SegFakeDatagram.String())
	}
	if !bytes.Contains([]byte(CapDatagram.String()), []byte("datagram")) {
		t.Errorf("CapDatagram.String() = %q: an unnamed capability cannot be reported as a shortfall", CapDatagram)
	}
}

func TestEmptyDecoyDatagramIsRefused(t *testing.T) {
	p := decoyPlan()
	p.Segments[0].Data = nil
	err := p.Validate(DefaultBudget())
	if !errors.Is(err, ErrBadValue) {
		t.Fatalf("err = %v, want ErrBadValue: an empty decoy carries no connection ID and shadows nothing", err)
	}
}
