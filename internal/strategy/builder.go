package strategy

import (
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// Builder is the scratch space a compiled Step mutates. It holds the bytes
// destined for the wire and the schedule that will be laid over them.
//
// Payload is rewritten in place by KindMutate and KindReframe ops, so it is the
// post-mutation, post-reframe byte string; Segs is the schedule over that
// string, built by the single KindSchedule op. Kind ordering guarantees the
// payload has stopped changing before any segment boundary is computed.
type Builder struct {
	Payload []byte
	Meta    tlsmsg.Meta
	Segs    []Segment
	Caps    Cap
	Budget  Budget
	Strict  bool // probe mode: any downgrade is an error, never a fallback

	notes    []string
	reframed bool
}

// Note records something the operator should be able to read back in
// `dpb strategy plan` or `dpb why`.
func (b *Builder) Note(format string, a ...any) {
	b.notes = append(b.notes, fmt.Sprintf(format, a...))
}

// Notes returns the notes accumulated so far.
func (b *Builder) Notes() []string { return b.notes }

// downgrade is the single place a strategy is allowed to do less than it was
// asked to. In Strict mode it is an error instead, because a prober that scores
// a downgraded plan under the original spec's name poisons every measurement
// derived from it.
func (b *Builder) downgrade(format string, a ...any) error {
	if b.Strict {
		return fmt.Errorf("%w: %s", ErrDowngrade, fmt.Sprintf(format, a...))
	}
	b.Note("downgrade: "+format, a...)
	return nil
}

// Reparse re-derives Meta from the current Payload. A KindMutate op that
// changes the payload's length must call it, or every downstream offset is
// silently stale.
//
// Truncated survives the reparse: only the reader knows why it stopped, and
// tlsmsg.Parse cannot tell.
func (b *Builder) Reparse() {
	truncated := b.Meta.Truncated
	port := b.Meta.DstPort
	b.Meta = tlsmsg.Parse(b.Payload, port)
	b.Meta.Truncated = truncated
	if len(b.Segs) > 0 {
		b.Note("reparse discarded %d staged segment(s): their offsets predate the payload rewrite", len(b.Segs))
		b.Segs = nil
	}
}

// ReframeFirstRecord rewrites the first TLS record of the payload into
// len(cuts)+1 structurally valid records carrying consecutive slices of its
// body, emitted as one contiguous byte string — one write, one TCP segment.
//
// cuts are body-relative and strictly increasing. This is where the measured
// rule is enforced, for every reframing op rather than only for tlsfrag:
// MEASUREMENTS.md §3.2 puts the boundary exactly at sniEnd, so a first record
// ending at or after sniEnd leaves the hostname intact for the DPI and the
// whole exercise is pointless. It is refused, not clamped, and not in Strict
// mode only — a plan that quietly ships the SNI unfragmented is the defect
// §3.5 records in the previous implementation.
func (b *Builder) ReframeFirstRecord(cuts []int) error {
	if b.reframed {
		return fmt.Errorf("%w: the first record was already reframed", ErrOneReframe)
	}
	if len(b.Segs) > 0 {
		return fmt.Errorf("%w: reframing after the write schedule was built", ErrOneSchedule)
	}
	if b.Meta.Proto != tlsmsg.ProtoTLS {
		return fmt.Errorf("%w: reframing needs a TLS record, the first message is %s", ErrNeedComplete, b.Meta.Proto)
	}
	if !b.Meta.Complete {
		return fmt.Errorf("%w: the first TLS record is not fully buffered", ErrNeedComplete)
	}
	if len(cuts) == 0 {
		return fmt.Errorf("%w: no cut positions", ErrBadValue)
	}
	for i := 1; i < len(cuts); i++ {
		if cuts[i] <= cuts[i-1] {
			return fmt.Errorf("%w: cuts %v are not strictly increasing", ErrBadValue, cuts)
		}
	}
	end := b.Meta.RecordEnd()
	if end <= b.Meta.BodyOff || end > len(b.Payload) {
		return fmt.Errorf("%w: first record ends at %d but the payload is %d bytes", ErrNeedComplete, end, len(b.Payload))
	}
	if limit, ok := b.Meta.MaxFirstRecordEnd(); ok && cuts[0] > limit {
		return fmt.Errorf("%w: first record would end at %d, the limit is sniEnd-1 = %d (sni at [%d,%d))",
			ErrCutAfterSNI, cuts[0], limit, b.Meta.SNIStart, b.Meta.SNIEnd)
	}

	rec, err := tlsmsg.SplitRecord(b.Payload[:end], cuts)
	if err != nil {
		return fmt.Errorf("reframe: %w", err)
	}
	out := make([]byte, 0, len(rec)+len(b.Payload)-end)
	out = append(out, rec...)
	out = append(out, b.Payload[end:]...)
	b.Payload = out
	b.reframed = true
	b.Note("reframed the first TLS record into %d records at %v, one write", len(cuts)+1, cuts)
	return nil
}

// Reframed reports whether the record layer has been rewritten. Meta still
// describes the payload as it was BEFORE the rewrite, because that is the
// coordinate system the user's anchors were written in; an op that needs fresh
// offsets calls Reparse.
func (b *Builder) Reframed() bool { return b.reframed }

// SplitAt lays a write schedule over the payload at the given absolute offsets.
// Offsets that fall outside the payload or repeat are dropped with a note, or
// refused in Strict mode.
func (b *Builder) SplitAt(offsets ...int) error {
	if len(b.Segs) > 0 {
		return fmt.Errorf("%w: the write schedule is already built", ErrOneSchedule)
	}
	n := len(b.Payload)
	if n == 0 {
		return fmt.Errorf("%w: nothing to split, the payload is empty", ErrBadValue)
	}
	clean := make([]int, 0, len(offsets))
	prev := 0
	for _, o := range offsets {
		if o <= prev || o >= n {
			if err := b.downgrade("dropped split offset %d: not strictly inside (%d, %d)", o, prev, n); err != nil {
				return err
			}
			continue
		}
		clean = append(clean, o)
		prev = o
	}
	max := b.Budget.orDefault().MaxSegments
	if len(clean)+1 > max {
		return fmt.Errorf("%w: %d offsets would make %d writes, max %d", ErrBudget, len(clean), len(clean)+1, max)
	}
	if len(clean) == 0 {
		if err := b.downgrade("no usable split offsets; sending the payload in one write"); err != nil {
			return err
		}
		b.Segs = []Segment{{Kind: SegStream, Data: b.Payload}}
		return nil
	}
	segs := make([]Segment, 0, len(clean)+1)
	start := 0
	for _, o := range clean {
		segs = append(segs, Segment{Kind: SegStream, Data: b.Payload[start:o]})
		start = o
	}
	segs = append(segs, Segment{Kind: SegStream, Data: b.Payload[start:]})
	b.Segs = segs
	return nil
}

// SetSegTTL sets a per-segment IP TTL. A missing capability is always an error,
// never a downgrade: emitting the segment with the default TTL is not a weaker
// version of disorder, it is a different, unmeasured strategy wearing its name.
func (b *Builder) SetSegTTL(i, ttl int) error {
	if i < 0 || i >= len(b.Segs) {
		return fmt.Errorf("%w: segment %d of %d", ErrBadValue, i, len(b.Segs))
	}
	if ttl < 1 || ttl > 255 {
		return fmt.Errorf("%w: ttl %d outside 1..255", ErrBadValue, ttl)
	}
	if !b.Caps.Has(CapSockTTL) {
		return fmt.Errorf("%w: per-segment TTL needs %s", ErrCapUnavailable, CapSockTTL)
	}
	b.Segs[i].TTL = ttl
	return nil
}

// MarkOOB inserts an out-of-band junk byte immediately after segment i, which
// is how byedpi's --oob places it: the receiver's TCP discards the urgent byte
// and the DPI, which usually does not, sees a different byte stream.
func (b *Builder) MarkOOB(i int, junk byte) error {
	if i < 0 || i >= len(b.Segs) {
		return fmt.Errorf("%w: segment %d of %d", ErrBadValue, i, len(b.Segs))
	}
	if !b.Caps.Has(CapOOB) {
		return fmt.Errorf("%w: an OOB byte needs %s", ErrCapUnavailable, CapOOB)
	}
	seg := Segment{Kind: SegOOBByte, Data: []byte{junk}, Note: "MSG_OOB junk byte"}
	b.Segs = append(b.Segs, Segment{})
	copy(b.Segs[i+2:], b.Segs[i+1:])
	b.Segs[i+1] = seg
	return nil
}

// Build freezes the builder into a Plan and runs gate 4 over it. A builder with
// no schedule emits the whole payload in one write, which is both the plain
// strategy and the tlsfrag strategy — MEASUREMENTS.md §3.1 measured two records
// in ONE TCP segment passing 3/3, so the primary emitter needs no second write.
func (b *Builder) Build(spec string) (Plan, error) {
	segs := b.Segs
	if len(segs) == 0 && len(b.Payload) > 0 {
		segs = []Segment{{Kind: SegStream, Data: b.Payload, Note: "whole first message, one write"}}
	}
	p := Plan{Spec: spec, Payload: b.Payload, Segments: segs, Notes: b.notes}
	if err := p.Validate(b.Budget.orDefault()); err != nil {
		return Plan{}, fmt.Errorf("plan %q: %w", label(spec), err)
	}
	return p, nil
}

func label(spec string) string {
	if spec == "" {
		return plainName
	}
	return spec
}
