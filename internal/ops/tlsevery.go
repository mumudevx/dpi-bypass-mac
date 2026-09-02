package ops

import (
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// maxPeriod bounds tlsevery's record size. A period at or above 2^14 exceeds
// the largest legal TLS record body, so it could never cut anything.
const maxPeriod = 1 << 14

// tlsEveryOp reframes the first TLS record into fixed-size records.
//
// It is the same mechanism as tlsfrag with more cuts, and the same rule decides
// it: the first record ends at `period`, so period must be at or below
// sniEnd-1. MEASUREMENTS.md §3 measured tlsrec-every-16 and tlsrec-every-64 at
// 3/3 through on all three blocked targets and tlsrec-every-256 at 0/3 — with
// the §3.2 geometry (SNI at [112,122), sniEnd-1 = 121) the predicate explains
// all three points, which is the strongest evidence that the rule, not the
// number, is what matters.
//
// It is not on the TR ladder. tlsfrag reaches the same place with one cut and
// therefore fewer records for a fragile terminator to reject; tlsevery is here
// for the prober and for the global ladder, where nothing has been measured.
func tlsEveryOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "tlsevery",
		Kind:        strategy.KindReframe,
		Caps:        capsStream,
		Determinism: strategy.DetRuleBased,
		Requires:    strategy.ReqComplete,
		Params: []strategy.ParamDoc{{
			Name:  "period",
			Probe: []string{"16", "64", "128", "256"},
			Doc:   "bytes per record; the first record ends here, so it must be at or below sniEnd-1",
		}},
		Summary: "reframe the first TLS record into fixed-size records",
		Source:  "MEASUREMENTS.md §3 (every-16 and every-64 pass 3/3, every-256 fails 0/3)",
		Risk:    95, // §5.1: record splitting survives 1 of 20 fragile-host trials
	}, func(a strategy.Args) (strategy.Step, error) {
		if _, ok := a["period"]; !ok {
			return nil, fmt.Errorf("%w: tlsevery needs period=<bytes>", strategy.ErrBadValue)
		}
		period, err := a.IntRange("period", 0, 1, maxPeriod)
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("tlsevery", capsStream, func(b *strategy.Builder) error {
			// A non-TLS first message is diagnosed by the builder, which names
			// the protocol; this check only decides whether the period can move
			// a boundary in a record that exists.
			if b.Meta.Proto == tlsmsg.ProtoTLS && period >= b.Meta.BodyLen {
				return fmt.Errorf("%w: period %d does not fit inside a %d-byte record body, so no record "+
					"boundary would move", strategy.ErrBadValue, period, b.Meta.BodyLen)
			}
			// The first cut is the one the rule judges: it alone decides where
			// record 1 ends, and record 1 is all this DPI parses.
			if err := refuseAfterSNI(b, "tlsevery", fmt.Sprintf("period=%d", period), period); err != nil {
				return err
			}
			cuts := make([]int, 0, b.Meta.BodyLen/period)
			for c := period; c < b.Meta.BodyLen; c += period {
				cuts = append(cuts, c)
			}
			return b.ReframeFirstRecord(cuts)
		}), nil
	})
}
