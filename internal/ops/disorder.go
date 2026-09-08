package ops

import (
	"fmt"

	"github.com/mumudevx/dpb/internal/strategy"
)

// disorderOp splits the first message and sends the leading segment with a TTL
// low enough that it dies before the origin but after the middlebox.
//
// Registered with full coverage and deliberately absent from the TR ladder.
// DOSSIER §3 rated it P1 on the strength of Turkish ByeDPI and zapret strategy
// strings; measured first-hand it is 0/10 on Türk Telekom (MEASUREMENTS.md
// §3.5). The socket mechanism itself works on Darwin — the failure is not the
// implementation, it is that reordering TCP segments cannot help against a
// middlebox that reassembles TCP (§3.1).
//
// It is mutually exclusive with oob on Darwin, enforced by strategy's
// composition gate: other kernels retransmit the OOB byte without URG and
// poison the stream, which is why zapret gates the pair to Linux and byedpi's
// --disoob measures 0/8 on macOS against 8/8 for --oob alone.
func disorderOp() strategy.Op {
	caps := capsStream | strategy.CapSockTTL
	return newOp(strategy.OpDoc{
		Name:        "disorder",
		Kind:        strategy.KindSchedule,
		Caps:        caps,
		Determinism: strategy.DetEmpirical,
		Params: []strategy.ParamDoc{
			{Name: "pos", Probe: []string{"1", "3", "snimid"}, Doc: "payload-absolute offset of the segment boundary; " +
				"an SNI or body anchor is resolved in record-body coordinates and converted"},
			{Name: "ttl", Default: "1", Probe: []string{"1", "2", "3"}, Doc: "IP TTL of the leading segment"},
		},
		Summary: "send the head with a low IP TTL so only the middlebox sees it",
		Source:  "MEASUREMENTS.md §3.5 (0/10 on TT)",
		Risk:    40, // unmeasured against fragile hosts; a TCP-level trick like split, but it drops bytes the origin never sees
	}, func(a strategy.Args) (strategy.Step, error) {
		p, err := requiredPos("disorder", a, "try pos=3")
		if err != nil {
			return nil, err
		}
		ttl, err := a.IntRange("ttl", 1, 1, 255)
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("disorder", caps, func(b *strategy.Builder) error {
			off, err := resolvePayloadPos(b, "disorder", p)
			if err != nil {
				return err
			}
			if err := b.SplitAt(off); err != nil {
				return err
			}
			// SplitAt is documented to produce ONE segment when it has no usable
			// offset, which outside Strict mode is a note rather than an error.
			// Lowering segment 0's TTL then puts the ENTIRE first message on the
			// wire with a hop limit of 1: it dies before the origin and the
			// connection is guaranteed dead, scored and cached under the name
			// "disorder". Refused for the same reason SetSegTTL refuses a
			// missing capability (builder.go).
			if len(b.Segs) < 2 {
				return fmt.Errorf("%w: disorder pos %s resolved to payload offset %d, which produced no "+
					"write boundary in a %d-byte message, so the whole first message would go out at ttl "+
					"%d and never reach the origin",
					strategy.ErrDowngrade, p, off, len(b.Payload), ttl)
			}
			// SetSegTTL refuses outright when the transport cannot set a TTL.
			// Emitting the head at the default TTL is not a weaker disorder, it
			// is a plain split — measured 0/5 — wearing disorder's name.
			return b.SetSegTTL(0, ttl)
		}), nil
	})
}
