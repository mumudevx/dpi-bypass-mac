package ops

import (
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// requiredPos reads a mandatory position parameter, so that a spec missing it
// fails at parse time with the op named rather than at connect time.
func requiredPos(op string, a strategy.Args, hint string) (strategy.Pos, error) {
	if _, ok := a["pos"]; !ok {
		return strategy.Pos{}, fmt.Errorf("%w: %s needs pos=<offset>; %s", strategy.ErrBadValue, op, hint)
	}
	return a.Pos("pos", strategy.Pos{})
}

// resolvePos maps a Pos onto this message, refusing an anchor that has nothing
// to attach to. An unresolvable anchor must never silently become offset 0: a
// one-byte TCP split is measured at 0/5 (MEASUREMENTS.md §3) while looking
// exactly like a working strategy in the logs.
func resolvePos(b *strategy.Builder, op string, p strategy.Pos) (int, error) {
	off, ok := p.Resolve(b.Meta)
	if !ok {
		return 0, fmt.Errorf("%w: %s pos %s does not resolve against this message (proto %s, sni %v, host %v)",
			strategy.ErrNeedSNI, op, p, b.Meta.Proto, b.Meta.HasSNI(), b.Meta.HasHost())
	}
	return off, nil
}

// splitOp writes the first message as two TCP segments.
//
// It is registered, fully tested, and deliberately ABSENT from the TR ladder.
// MEASUREMENTS.md §3.1 measured every two-segment split at 0/5 on Türk Telekom,
// including one cut inside the SNI hostname, while two TLS records inside a
// SINGLE segment went through 3/3: this DPI reassembles TCP, so segment
// boundaries are invisible to it and no split can help. The op stays in the
// prober's sweep because a middlebox that does not reassemble would light it
// up, and §4 is explicit that one ISP on one day is not a law.
func splitOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "split",
		Kind:        strategy.KindSchedule,
		Caps:        capsStream,
		Determinism: strategy.DetEmpirical,
		Params: []strategy.ParamDoc{{
			Name:  "pos",
			Probe: []string{"1", "2", "3", "5", "snimid"},
			Doc:   "absolute payload offset of the segment boundary",
		}},
		Summary: "plain two-segment TCP split",
		Source:  "MEASUREMENTS.md §3.1 (0/5 on TT: the DPI reassembles TCP)",
		Risk:    0, // §5.1: tcpsplit-in-sni left all 20 fragile-host trials working
	}, func(a strategy.Args) (strategy.Step, error) {
		p, err := requiredPos("split", a, "try pos=1 or pos=snimid")
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("split", capsStream, func(b *strategy.Builder) error {
			off, err := resolvePos(b, "split", p)
			if err != nil {
				return err
			}
			return b.SplitAt(off)
		}), nil
	})
}
