package ops

import (
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// oobOp splits the first message and sends one out-of-band (MSG_OOB) junk byte
// at the boundary.
//
// The receiving TCP strips the urgent byte from the in-band stream; a DPI that
// does not sees a byte the origin never receives, and its ClientHello parse is
// shifted by one. MEASUREMENTS.md §3 measured oob-at-1 and oob-at-3 at 3/3
// through on all three blocked targets.
//
// It is the LAST rung of the TR ladder and must stay there: §5.1 measured it at
// 0/20 against fragile hosts — every Turkish bank and .gov.tr endpoint tested
// broke — and 6/8 on the ordinary controls, making it the only emitter that
// also degrades sites nothing is wrong with. Reaching it means everything
// gentler has already failed on this host.
func oobOp() strategy.Op {
	caps := capsStream | strategy.CapOOB
	return newOp(strategy.OpDoc{
		Name:        "oob",
		Kind:        strategy.KindSchedule,
		Caps:        caps,
		Determinism: strategy.DetEmpirical,
		Params: []strategy.ParamDoc{
			{Name: "pos", Probe: []string{"1", "3"}, Doc: "absolute payload offset the junk byte follows"},
			{Name: "junk", Default: "1", Probe: []string{"1", "97"}, Doc: "the out-of-band byte value, 0..255"},
		},
		Summary: "MSG_OOB junk byte at a split point",
		Source:  "MEASUREMENTS.md §3 (3/3 through) and §5.1 (0/20 fragile, 6/8 controls)",
		Risk:    100, // the most destructive rung on the ladder
	}, func(a strategy.Args) (strategy.Step, error) {
		p, err := requiredPos("oob", a, "try pos=1")
		if err != nil {
			return nil, err
		}
		junk, err := a.IntRange("junk", 1, 0, 255)
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("oob", caps, func(b *strategy.Builder) error {
			off, err := resolvePos(b, "oob", p)
			if err != nil {
				return err
			}
			if err := b.SplitAt(off); err != nil {
				return err
			}
			return b.MarkOOB(0, byte(junk))
		}), nil
	})
}
