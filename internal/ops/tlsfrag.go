// Package ops is the emitter set: every desync technique this tool can express,
// each one a strategy.Op that compiles to a pure mutation of a strategy.Builder.
//
// Nothing here does I/O. An op turns a parsed first message into a Plan, and the
// Plan is a value a unit test can read byte for byte. MEASUREMENTS.md §3.3 is the
// reason: the one code path that expressed the measured DPI rule in the previous
// implementation was welded to a socket, sat at 0% coverage, and shipped with an
// inert knob and no check that its record cut landed before sniEnd.
//
// tlsfrag is the primary emitter and the whole point of the design. Everything
// else is a ladder rung, a prober diagnostic, or an op that exists only so that
// asking for it produces a cited refusal instead of "unknown op".
package ops

import (
	"fmt"
	"sync"

	"github.com/mumudevx/dpb/internal/strategy"
)

// capsStream is what every byte-reframing and byte-scheduling op needs: a
// stream socket with Nagle disabled, so a multi-write schedule reaches the wire
// as separate segments instead of being coalesced back into one.
const capsStream = strategy.CapStreamWrite | strategy.CapNoDelay

// basicOp is the shape of every op here: an OpDoc that defines Name/Kind/Caps
// through strategy.Base, plus a Compile that closes over validated parameters.
type basicOp struct {
	strategy.Base
	compile func(strategy.Args) (strategy.Step, error)
}

func (o basicOp) Compile(a strategy.Args) (strategy.Step, error) { return o.compile(a) }

func newOp(d strategy.OpDoc, c func(strategy.Args) (strategy.Step, error)) strategy.Op {
	return basicOp{Base: strategy.Base{D: d}, compile: c}
}

// All returns one fresh instance of every op this build ships, in no particular
// order — Registry.Docs sorts by (Kind, Name) for display.
func All() []strategy.Op {
	ops := []strategy.Op{
		hostCaseOp(),
		hostSpellOp(),
		hostDotOp(),
		hostPadOp(),
		tlsPadOp(),
		tlsFragOp(),
		tlsEveryOp(),
		chunkOp(),
		splitOp(),
		disorderOp(),
		oobOp(),
		quicFakeOp(),
	}
	return append(ops, unreachableOps()...)
}

// Register installs the whole set into r. It panics on a duplicate name, which
// is strategy.Registry's contract: registration is a build-time act.
func Register(r *strategy.Registry) {
	for _, o := range All() {
		r.Register(o)
	}
}

// NewRegistry returns a private registry holding the whole op set. Tests and
// the prober use it to compile specs without touching process-global state.
func NewRegistry() *strategy.Registry {
	r := strategy.NewRegistry()
	Register(r)
	return r
}

// Install registers the set into strategy.Default(), which is the registry
// strategy.Parse, strategy.MustParse and strategy.Ladder consult. It is safe to
// call more than once and returns the default registry.
//
// This is deliberately NOT done from an init: internal/strategy's own test
// binary registers a stub op set into the same default registry, so an
// init-time registration here would panic that build with a duplicate name and
// take M3's tests down with it. Every entry point that parses a user-supplied
// spec must call Install once at start-up; a blank import is not enough.
func Install() *strategy.Registry {
	r := strategy.Default()
	installOnce.Do(func() { Register(r) })
	return r
}

var installOnce sync.Once

// tlsFragOp is the shipped rung-2 emitter.
//
// It reframes the first TLS record into two structurally valid records carrying
// consecutive halves of the same body, concatenated into ONE write. The rule it
// enforces is MEASUREMENTS.md §3.2, measured over 66 shuffled trials on Türk
// Telekom AS9121 with both records in a single TCP segment:
//
//	sniStart-20 .. sniEnd-1   3/3 through on discord.com and discord.gg
//	sniEnd, +1, +20, +200     0/3, blocked
//
// The DPI parses only the first record of a connection as a ClientHello, so a
// first record ending at or after sniEnd still carries the whole hostname and
// the flow is matched exactly as if nothing had been done. That case is
// REFUSED with strategy.ErrCutAfterSNI, never clamped and never emitted:
// §3.5 records that the previous implementation "never verified the cut landed
// before sniEnd", and a plan that quietly ships the SNI intact is worse than no
// plan at all, because the user believes they are protected.
func tlsFragOp() strategy.Op {
	return newOp(strategy.OpDoc{
		Name:        "tlsfrag",
		Kind:        strategy.KindReframe,
		Caps:        capsStream,
		Determinism: strategy.DetRuleBased,
		Requires:    strategy.ReqComplete | strategy.ReqSNI,
		Params: []strategy.ParamDoc{{
			Name:  "pos",
			Probe: []string{"snimid", "sniend-1", "snistart", "snistart-20", "1"},
			Doc:   "body-relative cut position; anything at or after sniEnd is refused",
		}},
		Summary: "reframe the first TLS record so the SNI hostname is not complete inside it",
		Source:  "MEASUREMENTS.md §3.2",
		// §5.1: 1 of 20 fragile-host trials survived record splitting, and all
		// ten fragile hosts were Turkish banks or .gov.tr. Rung 2 is safe only
		// because rung 1 is plain.
		Risk: 95,
	}, func(a strategy.Args) (strategy.Step, error) {
		if _, ok := a["pos"]; !ok {
			return nil, fmt.Errorf("%w: tlsfrag needs pos=<offset>; try pos=snimid, the position "+
				"MEASUREMENTS.md §3.3 records as strictly dominant", strategy.ErrBadValue)
		}
		p, err := a.Pos("pos", strategy.Pos{})
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("tlsfrag", capsStream, func(b *strategy.Builder) error {
			// Record-body coordinates: ReframeFirstRecord's cuts and the §3.2
			// rule are both stated in them. See split.go for the two systems.
			cut, err := resolveBodyPos(b, "tlsfrag", p)
			if err != nil {
				return err
			}
			if err := refuseAfterSNI(b, "tlsfrag", p.String(), cut); err != nil {
				return err
			}
			return b.ReframeFirstRecord([]int{cut})
		}), nil
	})
}

// refuseAfterSNI is the load-bearing predicate, checked here so the error can
// quote the token the user actually typed. Builder.ReframeFirstRecord applies
// the same rule to every reframer and is the backstop; this is the diagnosis.
func refuseAfterSNI(b *strategy.Builder, op, token string, firstRecordEnd int) error {
	limit, ok := b.Meta.MaxFirstRecordEnd()
	if !ok {
		return nil // no hostname to hide; there is nothing for the rule to say
	}
	if firstRecordEnd > limit {
		return fmt.Errorf("%w: %s %s would end the first record at %d, but the SNI %q occupies [%d,%d) "+
			"of the record body, so the hostname would still be complete inside record 1 and the DPI "+
			"would match it exactly as if nothing had been done; the limit is sniEnd-1 = %d "+
			"(MEASUREMENTS.md §3.2)",
			strategy.ErrCutAfterSNI, op, token, firstRecordEnd, b.Meta.ServerName,
			b.Meta.SNIStart, b.Meta.SNIEnd, limit)
	}
	return nil
}
