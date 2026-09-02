package strategy

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// SegKind is what the sender does with a segment's bytes.
type SegKind uint8

const (
	SegStream  SegKind = iota // ordinary write; contributes to the payload
	SegOOBByte                // MSG_OOB junk byte; NOT part of the payload
	SegFakeRaw                // raw-injected decoy packet; NOT part of the payload
)

var segKindNames = [...]string{"stream", "oob", "fakeraw"}

func (k SegKind) String() string {
	if int(k) >= len(segKindNames) {
		return fmt.Sprintf("segkind(%d)", uint8(k))
	}
	return segKindNames[k]
}

type Segment struct {
	Kind  SegKind
	Data  []byte
	TTL   int // 0 = leave the socket default
	Delay time.Duration
	Note  string
}

type Budget struct {
	MaxSegments   int
	MinSegment    int
	MaxTotalDelay time.Duration
	MaxPayload    int
}

// DefaultBudget is the shipped budget. MaxSegments=16 is DOSSIER §3's cap and
// doubles as the guard for the XNU `if_sndbyte_unsent >= 0` panic, which is
// provoked by a high volume of small writes; MaxPayload=64 KiB matches
// flow.ReadFirstMessage's cap.
func DefaultBudget() Budget {
	return Budget{MaxSegments: 16, MinSegment: 1,
		MaxTotalDelay: 250 * time.Millisecond, MaxPayload: 64 << 10}
}

func (b Budget) orDefault() Budget {
	if b == (Budget{}) {
		return DefaultBudget()
	}
	return b
}

// Plan is a pure value. Invariant, checked on every Build and fuzzed:
// concatenating every SegStream Data in emission order equals Payload.
//
// Payload is the byte string that is actually destined for the wire, after any
// KindMutate rewrite and any KindReframe record split. The invariant therefore
// says that the SCHEDULE cannot corrupt the stream: the worst a chunk/split/oob
// op can do is fail to help.
type Plan struct {
	Spec     string
	Payload  []byte
	Segments []Segment
	Notes    []string
}

// Caps is what a transport must provide to emit this plan. It is derived from
// the segments, not from the spec, so a plan that was downgraded asks for
// exactly what it still needs.
func (p Plan) Caps() Cap {
	c := CapStreamWrite
	if len(p.Segments) > 1 {
		// More than one write only behaves as intended when Nagle is off;
		// otherwise the kernel coalesces the segments back together.
		c |= CapNoDelay
	}
	for _, s := range p.Segments {
		if s.TTL != 0 {
			c |= CapSockTTL
		}
		switch s.Kind {
		case SegOOBByte:
			c |= CapOOB
		case SegFakeRaw:
			c |= CapRawInject
		}
	}
	return c
}

// StreamBytes is everything the peer's TCP will reassemble: stream segments
// only, so an OOB junk byte and a raw decoy are excluded by construction.
func (p Plan) StreamBytes() []byte {
	n := 0
	for _, s := range p.Segments {
		if s.Kind == SegStream {
			n += len(s.Data)
		}
	}
	if n == 0 {
		return nil
	}
	out := make([]byte, 0, n)
	for _, s := range p.Segments {
		if s.Kind == SegStream {
			out = append(out, s.Data...)
		}
	}
	return out
}

func (p Plan) WriteCount() int { return len(p.Segments) }

// TotalDelay is the wall time the sender will spend sleeping between writes.
func (p Plan) TotalDelay() time.Duration {
	var d time.Duration
	for _, s := range p.Segments {
		d += s.Delay
	}
	return d
}

// Validate is gate 4. It rejects a plan that exceeds the budget, and — the
// invariant that matters most — one whose segments do not reassemble into its
// payload.
func (p Plan) Validate(b Budget) error {
	b = b.orDefault()
	if n := len(p.Segments); n > b.MaxSegments {
		return fmt.Errorf("%w: %d segments, max %d", ErrBudget, n, b.MaxSegments)
	}
	if b.MaxPayload > 0 && len(p.Payload) > b.MaxPayload {
		return fmt.Errorf("%w: payload %d bytes, max %d", ErrBudget, len(p.Payload), b.MaxPayload)
	}
	for i, s := range p.Segments {
		if s.Delay < 0 {
			return fmt.Errorf("%w: segment %d has a negative delay", ErrBadValue, i)
		}
		if s.TTL < 0 || s.TTL > 255 {
			return fmt.Errorf("%w: segment %d has ttl %d, want 0..255", ErrBadValue, i, s.TTL)
		}
		switch s.Kind {
		case SegStream:
			if len(s.Data) < b.MinSegment {
				return fmt.Errorf("%w: segment %d is %d bytes, min %d", ErrBudget, i, len(s.Data), b.MinSegment)
			}
		case SegOOBByte:
			if len(s.Data) != 1 {
				return fmt.Errorf("%w: segment %d is an OOB byte but carries %d bytes", ErrBadValue, i, len(s.Data))
			}
		case SegFakeRaw:
			if len(s.Data) == 0 {
				return fmt.Errorf("%w: segment %d is an empty raw packet", ErrBadValue, i)
			}
		default:
			return fmt.Errorf("%w: segment %d has kind %s", ErrBadValue, i, s.Kind)
		}
	}
	if d := p.TotalDelay(); b.MaxTotalDelay > 0 && d > b.MaxTotalDelay {
		return fmt.Errorf("%w: total delay %s, max %s", ErrBudget, d, b.MaxTotalDelay)
	}
	if got := p.StreamBytes(); !bytes.Equal(got, p.Payload) {
		return fmt.Errorf("%w: %d stream bytes vs %d payload bytes", ErrStreamCorrupt, len(got), len(p.Payload))
	}
	return nil
}

func (p Plan) String() string { return p.Spec }

// Describe renders the segment list for `dpb strategy plan` and for a debug
// log. It never prints payload bytes: a plan carries a hostname.
func (p Plan) Describe() []string {
	label := p.Spec
	if label == "" {
		label = plainName
	}
	out := []string{fmt.Sprintf("%s: %d bytes in %d write(s)", label, len(p.Payload), len(p.Segments))}
	for i, s := range p.Segments {
		line := fmt.Sprintf("  %d. %-7s %5d B", i+1, s.Kind, len(s.Data))
		if s.TTL != 0 {
			line += fmt.Sprintf(" ttl=%d", s.TTL)
		}
		if s.Delay != 0 {
			line += " delay=" + s.Delay.String()
		}
		if s.Note != "" {
			line += "  " + s.Note
		}
		out = append(out, line)
	}
	for _, n := range p.Notes {
		out = append(out, "  note: "+n)
	}
	return out
}

// Summary is Describe on one line, for a log field.
func (p Plan) Summary() string { return strings.Join(p.Describe(), "; ") }
