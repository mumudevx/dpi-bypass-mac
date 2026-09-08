package ops

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mumudevx/dpb/internal/httpmsg"
	"github.com/mumudevx/dpb/internal/strategy"
)

// The host mutators are the port-80 half of the emitter set. They rewrite the
// Host header so a DPI matching its literal bytes misses, while every RFC 9110
// conformant origin still routes the request to the same vhost.
//
// DOSSIER §3 rates the family P2: cheap, unprivileged, and of diminishing value
// in 2026 because almost everything is HTTPS. They are not on the TR ladder,
// which is a TLS ladder; a plaintext flow gets them through the prober or an
// explicit spec.
//
// Every mutator here changes the payload's length or bytes and therefore calls
// Builder.Reparse, so a later scheduling op computes its offsets against the
// message that will actually be written. A mutator that cannot change anything
// returns an error rather than silently doing nothing — the inert-knob defect
// MEASUREMENTS.md §3.5 records.

// ErrNotApplicable means the op understood the message and has nothing it can
// change: a Host value that already ends in the root dot, a header already
// spelled the way it was asked to be, a Host holding an IP literal where a
// trailing dot is meaningless. It is a refusal, not a failure — the ladder
// moves on to the next rung — and it is typed so that no caller has to
// string-match httpmsg's error text to tell the two apart.
var ErrNotApplicable = errors.New("ops: op cannot apply to this first message")

// mutate wraps an httpmsg rewrite as a Step: apply, replace the payload,
// reparse.
func mutate(name string, caps strategy.Cap, fn func([]byte) ([]byte, error)) strategy.Step {
	return strategy.StepFunc(name, caps, func(b *strategy.Builder) error {
		if !b.Meta.HasHost() {
			return fmt.Errorf("%w: %s rewrites the HTTP Host header and this message has none (proto %s)",
				strategy.ErrNeedHost, name, b.Meta.Proto)
		}
		out, err := fn(b.Payload)
		if err != nil {
			return fmt.Errorf("%s: %w: %w", name, ErrNotApplicable, err)
		}
		b.Payload = out
		b.Reparse()
		return nil
	})
}

// hostCaseOp respells the Host header name. Field names are case-insensitive
// (RFC 9110 §5.1), so an origin cannot tell the difference and a DPI matching
// the literal bytes "Host:" can.
func hostCaseOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "hostcase",
		Kind:        strategy.KindMutate,
		Caps:        strategy.CapStreamWrite,
		Determinism: strategy.DetEmpirical,
		Requires:    strategy.ReqComplete | strategy.ReqHost,
		Summary:     "respell the Host header name as " + httpmsg.DefaultSpell,
		Source:      "DOSSIER §3 (P2)",
		Risk:        5,
	}, func(strategy.Args) (strategy.Step, error) {
		return mutate("hostcase", strategy.CapStreamWrite, httpmsg.HostCase), nil
	})
}

// hostSpellOp is hostcase with the spelling chosen by the caller, so the prober
// can sweep spellings against a DPI that special-cases one of them.
func hostSpellOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "hostspell",
		Kind:        strategy.KindMutate,
		Caps:        strategy.CapStreamWrite,
		Determinism: strategy.DetEmpirical,
		Requires:    strategy.ReqComplete | strategy.ReqHost,
		Params: []strategy.ParamDoc{{
			Name:    "spell",
			Default: httpmsg.DefaultSpell,
			Probe:   []string{"hoSt", "HOST", "hosT"},
			Doc:     "case variant of \"host\" to write as the header name",
		}},
		Summary: "respell the Host header name",
		Source:  "DOSSIER §3 (P2)",
		Risk:    5,
	}, func(a strategy.Args) (strategy.Step, error) {
		spell := a.Str("spell", httpmsg.DefaultSpell)
		// Rejected at parse time, not at connect time: a spelling that is not a
		// case variant of "host" would rename the header rather than respell it,
		// and the user must learn that from the spec they typed.
		if !strings.EqualFold(spell, "host") {
			return nil, fmt.Errorf("%w: spell=%q is not a case variant of \"host\"", strategy.ErrBadValue, spell)
		}
		return mutate("hostspell", strategy.CapStreamWrite, func(b []byte) ([]byte, error) {
			return httpmsg.HostSpell(b, spell)
		}), nil
	})
}

// hostDotOp appends the DNS root dot to the Host value. The name still resolves
// and the origin still matches its vhost; a DPI comparing against a dot-less
// list does not.
func hostDotOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "hostdot",
		Kind:        strategy.KindMutate,
		Caps:        strategy.CapStreamWrite,
		Determinism: strategy.DetEmpirical,
		Requires:    strategy.ReqComplete | strategy.ReqHost,
		Summary:     "append the DNS root dot to the Host header value",
		Source:      "DOSSIER §3 (P2)",
		Risk:        15,
	}, func(strategy.Args) (strategy.Step, error) {
		return mutate("hostdot", strategy.CapStreamWrite, httpmsg.HostDot), nil
	})
}

// hostPadOp inserts a filler header before the Host line, pushing the hostname
// further into the request.
//
// DOSSIER §3 records why this is a diagnostic and not a ladder rung: if the
// smallest pad that works approaches the MTU, the DPI is not reassembling the
// stream and a plain split is the better fix. The prober reads that answer; the
// ladder does not carry it.
func hostPadOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "hostpad",
		Kind:        strategy.KindMutate,
		Caps:        strategy.CapStreamWrite,
		Determinism: strategy.DetEmpirical,
		Requires:    strategy.ReqComplete | strategy.ReqHost,
		Params: []strategy.ParamDoc{{
			Name:    "len",
			Default: "64",
			Probe:   []string{"64", "300", "600", "1200", "1500"},
			Doc:     fmt.Sprintf("bytes of filler header, %d..%d", httpmsg.MinPad, httpmsg.MaxPad),
		}},
		Summary: "insert a filler header before the Host line",
		Source:  "DOSSIER §3 (P2, diagnostic)",
		Risk:    20,
	}, func(a strategy.Args) (strategy.Step, error) {
		n, err := a.IntRange("len", 64, httpmsg.MinPad, httpmsg.MaxPad)
		if err != nil {
			return nil, err
		}
		return mutate("hostpad", strategy.CapStreamWrite, func(b []byte) ([]byte, error) {
			return httpmsg.HostPad(b, n)
		}), nil
	})
}
