package emit

import (
	"context"
	"fmt"
	"time"

	"github.com/mumudevx/dpb/internal/strategy"
)

// Sender executes a Plan against a Transport. It is stateless per connection and
// safe for concurrent use: every mutable thing it touches (the token bucket)
// carries its own lock, and the per-plan TTL bookkeeping lives on the stack.
type Sender struct {
	// Gov bounds the process-wide rate of multi-write plans. Nil means ungoverned,
	// which is correct for the prober, where every attempt must emit exactly the
	// segments it claims to have emitted or the measurement is a lie.
	Gov  Governor
	Logf func(string, ...any)
}

func (s *Sender) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	}
}

// Send emits every segment of p in order.
//
// Errors are wrapped, never classified here: flow.Classify owns the mapping from
// a wire error to a flow.Failure, and emit must not import flow (flow imports
// emit). The underlying syscall error is preserved through %w so errors.Is on
// syscall.ECONNRESET / EPIPE still works at the call site.
func (s *Sender) Send(ctx context.Context, t Transport, p strategy.Plan) error {
	if t == nil {
		return fmt.Errorf("emit: send %q: nil transport", p.Spec)
	}
	if len(p.Segments) == 0 {
		if len(p.Payload) != 0 {
			return fmt.Errorf("emit: send %q: %d payload bytes but no segments", p.Spec, len(p.Payload))
		}
		return nil
	}

	have, need := t.Caps(), p.Caps()
	if missing := have.Missing(need); missing != 0 {
		return fmt.Errorf("%w: plan %q needs %s, transport has %s (missing %s)",
			ErrCapUnavailable, planName(p), need, have, missing)
	}

	segs := p.Segments
	// A single-write plan can never reach the governor. That is not an
	// optimisation: tlsfrag — the primary emitter, the one carrying the measured
	// rule — is exactly one write, so the XNU small-write guard cannot degrade the
	// strategy that matters. Only rungs 3-5 are governed.
	if s.Gov != nil && len(segs) > 1 {
		if granted := s.Gov.Reserve(len(segs)); granted < len(segs) {
			segs = coalesce(segs, granted)
			s.logf("emit: governor coalesced %q from %d writes to %d (small-write budget short)",
				planName(p), len(p.Segments), len(segs))
		}
	}

	ttlDirty := false
	defer func() {
		// The socket outlives this plan: it becomes the relay for the rest of the
		// connection. Leaving IP_TTL at 1 there would black-hole every subsequent
		// byte, so the restore runs on the error path too.
		if ttlDirty {
			if err := t.ResetTTL(); err != nil {
				s.logf("emit: WARNING could not restore the default hop limit on %s: %v; "+
					"this connection may black-hole — close it rather than relaying on it",
					t.Remote(), err)
			}
		}
	}()

	for i, seg := range segs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("emit: %q aborted before segment %d/%d: %w", planName(p), i+1, len(segs), err)
		}
		if seg.Delay > 0 {
			if err := sleep(ctx, seg.Delay); err != nil {
				return fmt.Errorf("emit: %q aborted in the delay before segment %d/%d: %w",
					planName(p), i+1, len(segs), err)
			}
		}

		switch {
		case seg.TTL != 0:
			if err := t.SetTTL(seg.TTL); err != nil {
				return fmt.Errorf("emit: %q segment %d/%d: set hop limit %d: %w",
					planName(p), i+1, len(segs), seg.TTL, err)
			}
			ttlDirty = true
		case ttlDirty:
			if err := t.ResetTTL(); err != nil {
				return fmt.Errorf("emit: %q segment %d/%d: restore hop limit: %w",
					planName(p), i+1, len(segs), err)
			}
			ttlDirty = false
		}

		if err := emitSegment(t, seg); err != nil {
			return fmt.Errorf("emit: %q segment %d/%d (%s, %d bytes): %w",
				planName(p), i+1, len(segs), seg.Kind, len(seg.Data), err)
		}
	}
	return nil
}

func emitSegment(t Transport, seg strategy.Segment) error {
	switch seg.Kind {
	case strategy.SegStream:
		n, err := t.Write(seg.Data)
		if err != nil {
			return err
		}
		if n != len(seg.Data) {
			return fmt.Errorf("%w: %d of %d bytes", ErrShortWrite, n, len(seg.Data))
		}
		return nil
	case strategy.SegOOBByte:
		n, err := t.WriteOOB(seg.Data)
		if err != nil {
			return err
		}
		if n != len(seg.Data) {
			return fmt.Errorf("%w: %d of %d bytes", ErrShortWrite, n, len(seg.Data))
		}
		return nil
	case strategy.SegFakeRaw:
		return t.InjectRaw(seg.Data)
	case strategy.SegFakeDatagram:
		// An ordinary write, as byedpi's desync_udp does it. The transport is a
		// connected datagram socket — CapDatagram says so and the Sender's cap
		// check has already refused the plan otherwise — so this write is one
		// packet and the decoy never mixes with the payload.
		n, err := t.Write(seg.Data)
		if err != nil {
			return err
		}
		if n != len(seg.Data) {
			return fmt.Errorf("%w: %d of %d bytes", ErrShortWrite, n, len(seg.Data))
		}
		return nil
	default:
		return fmt.Errorf("emit: unknown segment kind %s", seg.Kind)
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

func planName(p strategy.Plan) string {
	if p.Spec == "" {
		return "plain"
	}
	return p.Spec
}

// coalesce folds adjacent stream segments together until at most max writes
// remain, copying rather than mutating so the caller's Plan (which the verdict
// store may hold) is untouched.
//
// It merges from the TAIL forwards. Every measured rule this tool encodes is
// about where the FIRST boundary falls — MEASUREMENTS.md §3.2 is a predicate on
// the end of the first TLS record — so when writes must be given up, the ones to
// give up are the late ones. A head-first merge would silently turn
// `chunk:size=12` into a plain write and keep the useless tail splits.
func coalesce(segs []strategy.Segment, max int) []strategy.Segment {
	if max < 1 || len(segs) <= max {
		return segs
	}
	out := make([]strategy.Segment, len(segs))
	copy(out, segs)

	for len(out) > max {
		i := -1
		for j := len(out) - 1; j >= 1; j-- {
			if mergeable(out[j-1], out[j]) {
				i = j
				break
			}
		}
		if i < 0 {
			// Nothing left to merge: every remaining boundary carries a TTL change,
			// a delay or an OOB byte, and merging across one would change what goes
			// on the wire. Over budget is better than wrong.
			break
		}
		merged := out[i-1]
		merged.Data = make([]byte, 0, len(out[i-1].Data)+len(out[i].Data))
		merged.Data = append(merged.Data, out[i-1].Data...)
		merged.Data = append(merged.Data, out[i].Data...)
		if merged.Note == "" {
			merged.Note = "coalesced"
		}

		next := make([]strategy.Segment, 0, len(out)-1)
		next = append(next, out[:i-1]...)
		next = append(next, merged)
		next = append(next, out[i+1:]...)
		out = next
	}
	return out
}

func mergeable(a, b strategy.Segment) bool {
	return a.Kind == strategy.SegStream && b.Kind == strategy.SegStream &&
		a.TTL == b.TTL && b.Delay == 0
}
