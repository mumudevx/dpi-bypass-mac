package ops

import (
	"fmt"

	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// maxChunk bounds the chunk size to one first message. Anything larger cannot
// produce a second segment.
const maxChunk = 64 << 10

// chunkOp writes the first message in fixed-size pieces.
//
// Ladder rung 3 (MEASUREMENTS.md §5.3). It is kept deliberately behind tlsfrag:
// §3.4 measured two independent shuffled sweeps of chunk size and got a
// non-monotonic curve that no simple model explains, while every point in §3.2
// follows from one rule. Chunking is a real bypass on this line and an
// unreliable one, so it is a fallback with a different mechanism, never the
// default.
//
// §3.4's curve — 1,2,3,4 and 12 through, 5,8,20,35,40,60,120 blocked — was
// measured with a harness that chunks the ENTIRE ClientHello. It is not this
// emitter's curve and must never be quoted as one: §3.4's own correction
// re-measured the shipped op and got a different, explicable set. A chunk size
// is meaningless without the write geometry it was measured under.
//
// The schedule covers the HEAD of the message, not all of it. strategy's budget
// caps a plan at 16 segments — DOSSIER §3's cap, and the guard against the XNU
// `if_sndbyte_unsent` panic that a high volume of small writes provokes — so
// chunking a 1502-byte ClientHello at size=12 would need 126 writes and is
// refused outright by Builder.SplitAt. This op therefore emits at most
// MaxSegments-1 chunks and puts the remainder in one final write.
//
// That geometry is not free, and the correction in MEASUREMENTS.md §3.4 is the
// reason chunkPrefixLimit below exists. With 15 boundaries available the chunked
// prefix covers only `(MaxSegments-1) * size` bytes, and the bypass requires
// that prefix to extend PAST the hostname — measured on this line with the
// shipped emitter:
//
//	chunk:size=   2      4      8      9     12     20
//	shipped op  RESET  RESET  RESET   PASS   PASS  RESET
//
// 9x15 = 135 > 5+sniEnd = 127 passes; 8x15 = 120 does not. (Necessary, not
// sufficient — size=20 covers 300 bytes and still fails.) A size whose prefix
// stops short of the SNI therefore ships the hostname intact inside one
// contiguous tail write: a plain write wearing chunk's name. It is REFUSED with
// ErrBudget, exactly as tlsevery refuses a period past sniEnd-1, so the ladder
// skips the rung and the prober records it as unmeasurable rather than caching
// a blocked measurement that is an artefact of this emitter's geometry — the
// failure §3.5 exists to forbid.
//
// Past that predicate the tail is what the measurement was taken over, the
// geometry is deterministic given (size, budget), and it is recorded in the
// plan's notes, so a probe result stays reproducible.
func chunkOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "chunk",
		Kind:        strategy.KindSchedule,
		Caps:        capsStream,
		Determinism: strategy.DetEmpirical,
		Requires:    strategy.ReqComplete,
		Params: []strategy.ParamDoc{{
			Name: "size",
			// Sizes 1..8 are gone: at the shipped 16-segment budget their
			// chunked prefix stops short of the SNI on a real ClientHello, so
			// they are refused rather than swept (MEASUREMENTS.md §3.4).
			Probe: []string{"12", "9", "20", "40", "120"},
			Doc: "bytes per write; the first MaxSegments-1 writes carry this many bytes and the " +
				"remainder goes in one, so the size must be large enough that the chunked prefix " +
				"ends past the SNI",
		}},
		Summary: "fixed-size write loop over the head of the first message",
		Source:  "MEASUREMENTS.md §3.4 (shipped-emitter correction: 9 and 12 through, 2/4/8/20 blocked)",
		Risk:    35, // §5.1: chunk-12 leaves 14 of 20 fragile-host trials working
	}, func(a strategy.Args) (strategy.Step, error) {
		if _, ok := a["size"]; !ok {
			return nil, fmt.Errorf("%w: chunk needs size=<bytes>", strategy.ErrBadValue)
		}
		size, err := a.IntRange("size", 0, 1, maxChunk)
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("chunk", capsStream, func(b *strategy.Builder) error {
			n := len(b.Payload)
			if size >= n {
				return fmt.Errorf("%w: chunk size %d covers the whole %d-byte message, so no write "+
					"boundary would move", strategy.ErrBadValue, size, n)
			}
			maxSegs := budgetOf(b).MaxSegments
			if maxSegs < 2 {
				return fmt.Errorf("%w: a budget of %d segment(s) cannot express a chunked write",
					strategy.ErrBudget, maxSegs)
			}
			offs := make([]int, 0, maxSegs-1)
			for o := size; o < n && len(offs) < maxSegs-1; o += size {
				offs = append(offs, o)
			}
			if want := (n + size - 1) / size; want > maxSegs {
				head := offs[len(offs)-1]
				// MEASUREMENTS.md §3.4 (correction): with the tail unchunked the
				// bypass requires the chunked prefix to end past the hostname.
				if limit, ok := chunkPrefixLimit(b.Meta); ok && head <= limit {
					return fmt.Errorf("%w: chunk:size=%d fills the %d-segment budget after %d bytes and "+
						"sends the remaining %d in one write, but the SNI %q ends at payload offset %d, so "+
						"the hostname would travel intact inside that tail and the DPI would match it "+
						"exactly as if nothing had been done; the chunked prefix must end past %d, which "+
						"needs size > %d at this budget (MEASUREMENTS.md §3.4)",
						strategy.ErrBudget, size, maxSegs, head, n-head, b.Meta.ServerName, limit,
						limit, limit/(maxSegs-1))
				}
				b.Note("chunk:size=%d chunked the first %d bytes into %d writes and put the remaining %d "+
					"bytes in one; chunking all %d bytes would need %d writes and the segment budget is %d",
					size, head, len(offs), n-head, n, want, maxSegs)
			}
			return b.SplitAt(offs...)
		}), nil
	})
}

// chunkPrefixLimit is the payload offset the chunked prefix must end PAST for
// the bypass to be possible: the last byte of the SNI hostname, in the same
// payload-absolute coordinates the write schedule is laid out in.
//
// Meta.SNIStart/SNIEnd are record-body offsets (see split.go on the two
// coordinate systems), so BodyOff is added. ok is false when there is no
// hostname to hide — a plaintext request or a hello with no server_name — where
// the rule has nothing to say and the geometry is judged by nothing.
func chunkPrefixLimit(m tlsmsg.Meta) (int, bool) {
	if !m.HasSNI() {
		return 0, false
	}
	return m.BodyOff + m.SNIEnd, true
}

// budgetOf reads a builder's budget, substituting the shipped default for the
// zero value the way strategy.Builder does internally.
func budgetOf(b *strategy.Builder) strategy.Budget {
	if b.Budget == (strategy.Budget{}) {
		return strategy.DefaultBudget()
	}
	return b.Budget
}
