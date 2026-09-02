package ops

import (
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// maxChunk bounds the chunk size to one first message. Anything larger cannot
// produce a second segment.
const maxChunk = 64 << 10

// chunkOp writes the first message in fixed-size pieces.
//
// Ladder rungs 3 and 4 (MEASUREMENTS.md §5.3). It is kept deliberately behind
// tlsfrag: §3.4 measured two independent shuffled sweeps of chunk size and got
// a non-monotonic curve — 1,2,3,4 and 12 through, 5, 8, 20, 35, 40, 60 and 120
// blocked — that no simple model explains, while every point in §3.2 follows
// from one rule. Chunking is a real bypass on this line and an unreliable one,
// so it is a fallback with a different mechanism, never the default.
//
// The schedule covers the HEAD of the message, not all of it. strategy's budget
// caps a plan at 16 segments — DOSSIER §3's cap, and the guard against the XNU
// `if_sndbyte_unsent` panic that a high volume of small writes provokes — so
// chunking a 1502-byte ClientHello at size=12 would need 126 writes and is
// refused outright by Builder.SplitAt. This op therefore emits at most
// MaxSegments-1 chunks and puts the remainder in one final write. Everything
// the DPI decides on lives in the first record's ClientHello, so the bytes that
// matter are chunked identically; what changes is the tail, which no measured
// mechanism reads. The geometry is deterministic given (size, budget) and is
// recorded in the plan's notes, so a probe result stays reproducible —
// §3.5 requires the prober to measure the emitter this tool actually ships
// rather than to import another implementation's numbers.
func chunkOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "chunk",
		Kind:        strategy.KindSchedule,
		Caps:        capsStream,
		Determinism: strategy.DetEmpirical,
		Requires:    strategy.ReqComplete,
		Params: []strategy.ParamDoc{{
			Name:  "size",
			Probe: []string{"12", "4", "2", "1", "3", "5", "8", "20", "40"},
			Doc:   "bytes per write",
		}},
		Summary: "fixed-size write loop over the head of the first message",
		Source:  "MEASUREMENTS.md §3.4 (non-monotonic; 4 and 12 through, 5/8/20/40 blocked)",
		Risk:    35, // §5.1: chunk-12 leaves 14 of 20 fragile-host trials working, chunk-4 13 of 20
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
				b.Note("chunk:size=%d chunked the first %d bytes into %d writes and put the remaining %d "+
					"bytes in one; chunking all %d bytes would need %d writes and the segment budget is %d",
					size, head, len(offs), n-head, n, want, maxSegs)
			}
			return b.SplitAt(offs...)
		}), nil
	})
}

// budgetOf reads a builder's budget, substituting the shipped default for the
// zero value the way strategy.Builder does internally.
func budgetOf(b *strategy.Builder) strategy.Budget {
	if b.Budget == (strategy.Budget{}) {
		return strategy.DefaultBudget()
	}
	return b.Budget
}
