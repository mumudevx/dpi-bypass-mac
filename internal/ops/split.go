package ops

import (
	"fmt"

	"github.com/mumudevx/dpb/internal/strategy"
)

// requiredPos reads a mandatory position parameter, so that a spec missing it
// fails at parse time with the op named rather than at connect time.
func requiredPos(op string, a strategy.Args, hint string) (strategy.Pos, error) {
	if _, ok := a["pos"]; !ok {
		return strategy.Pos{}, fmt.Errorf("%w: %s needs pos=<offset>; %s", strategy.ErrBadValue, op, hint)
	}
	return a.Pos("pos", strategy.Pos{})
}

// There are two coordinate systems in play and they differ by BodyOff (5 for
// TLS). tlsmsg.Meta states the SNI extent and the record body length in
// RECORD-BODY coordinates, because that is the system the measured rule of
// MEASUREMENTS.md §3.2 is written in; Builder.SplitAt and Builder.Payload are
// indexed in PAYLOAD-ABSOLUTE coordinates. strategy.Pos.Resolve answers in the
// anchor's own system, so every call site has to say which one it wants — and
// the two resolvers below are named for the answer they return so that a future
// op cannot pick the wrong one silently. Handing a body-relative offset to
// SplitAt is what made split/oob/disorder cut five bytes early and inverted
// snistart and sniend against the token the user typed.
//
// An unresolvable anchor must never silently become offset 0: a one-byte TCP
// split is measured at 0/5 (MEASUREMENTS.md §3) while looking exactly like a
// working strategy in the logs.

// bodyAnchor reports whether an anchor resolves in record-body coordinates. The
// SNI and body families do; AnchorAbs is whatever the consumer indexes, and the
// HTTP host family is already payload-absolute.
func bodyAnchor(a strategy.Anchor) bool {
	switch a {
	case strategy.AnchorSNIStart, strategy.AnchorSNIMid, strategy.AnchorSNIEnd, strategy.AnchorBodyMid:
		return true
	}
	return false
}

// resolveBodyPos maps a Pos onto an offset into the FIRST TLS RECORD'S BODY —
// the system Builder.ReframeFirstRecord's cuts and Meta.MaxFirstRecordEnd are
// expressed in. Reframing ops want this one.
func resolveBodyPos(b *strategy.Builder, op string, p strategy.Pos) (int, error) {
	off, ok := p.Resolve(b.Meta)
	if !ok {
		return 0, unresolvable(b, op, p)
	}
	return off, nil
}

// resolvePayloadPos maps a Pos onto an offset into the PAYLOAD — the system
// Builder.SplitAt indexes. Scheduling ops want this one.
//
// Meta.BodyOff is 5 for TLS and 0 for every other first message, so adding it
// for the body-relative anchors is the identity on HTTP and QUIC and the whole
// correction on TLS.
func resolvePayloadPos(b *strategy.Builder, op string, p strategy.Pos) (int, error) {
	off, ok := p.Resolve(b.Meta)
	if !ok {
		return 0, unresolvable(b, op, p)
	}
	if bodyAnchor(p.Anchor) {
		off += b.Meta.BodyOff
	}
	return off, nil
}

func unresolvable(b *strategy.Builder, op string, p strategy.Pos) error {
	return fmt.Errorf("%w: %s pos %s does not resolve against this message (proto %s, sni %v, host %v)",
		strategy.ErrNeedSNI, op, p, b.Meta.Proto, b.Meta.HasSNI(), b.Meta.HasHost())
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
			Doc: "payload-absolute offset of the segment boundary; an SNI or body anchor is " +
				"resolved in record-body coordinates and converted, so snimid really does land " +
				"inside the hostname",
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
			off, err := resolvePayloadPos(b, "split", p)
			if err != nil {
				return err
			}
			return b.SplitAt(off)
		}), nil
	})
}
