package strategy

import (
	"fmt"
	"strings"

	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// The two ops that cannot share a spec. zapret gates the pair to Linux because
// other kernels retransmit the OOB byte without URG and poison the stream, and
// byedpi's --disoob measures 0/8 on macOS against 8/8 for --oob alone. dpb only
// ships for darwin, so the pair is refused unconditionally rather than behind a
// GOOS check that would let a linux test claim the guard works.
const (
	opDisorder = "disorder"
	opOOB      = "oob"
)

// checkComposition is gate 2. It runs on the ops as typed, before they are
// sorted, so an error can quote what the user actually wrote.
func checkComposition(ops []Op) error {
	var (
		reframe, schedule []string
		byName            = make(map[string]bool, len(ops))
	)
	for _, o := range ops {
		d := o.Doc()
		switch o.Kind() {
		case KindReframe:
			reframe = append(reframe, d.Name)
		case KindSchedule:
			schedule = append(schedule, d.Name)
		}
		byName[d.Name] = true
	}
	// The specific diagnosis comes first. Both ops schedule writes, so the
	// one-scheduler rule below would otherwise swallow this pair and answer a
	// cited platform question with a generic one.
	if byName[opDisorder] && byName[opOOB] {
		return fmt.Errorf("%w: %s and %s are mutually exclusive on darwin — zapret gates the pair to Linux "+
			"because other kernels retransmit the OOB byte without URG and poison the stream, and byedpi's "+
			"--disoob measures 0/8 on macOS against 8/8 for --oob alone",
			ErrIncompatible, opDisorder, opOOB)
	}
	if len(reframe) > 1 {
		return fmt.Errorf("%w: %s both rewrite the TLS record layer", ErrOneReframe, strings.Join(reframe, " and "))
	}
	if len(schedule) > 1 {
		return fmt.Errorf("%w: %s both map the payload onto writes", ErrOneSchedule, strings.Join(schedule, " and "))
	}
	return nil
}

// CheckAgainst is gates 2 and 3 for a connection that is about to happen: does
// this transport have what the strategy needs, and does this first message have
// what the strategy reads.
//
// A profile naming a strategy the selected transport cannot satisfy must refuse
// to load with the shortfall named. Silently emitting a weaker plan is how the
// previous implementation's flagship profile demanded root and then shipped the
// SNI unfragmented anyway.
func (s Strategy) CheckAgainst(have Cap, m tlsmsg.Meta) error {
	if miss := have.Missing(s.Caps()); miss != 0 {
		return fmt.Errorf("%w: %s needs %s, the transport offers %s, missing %s",
			ErrCapUnavailable, s.Label(), s.Caps(), have, miss)
	}
	req := s.Requires()
	if req&ReqComplete != 0 && !m.Complete {
		return fmt.Errorf("%w: %s needs the whole first message; it is %d bytes and truncated=%v",
			ErrNeedComplete, s.Label(), m.BodyLen, m.Truncated)
	}
	if req&ReqSNI != 0 && !m.HasSNI() {
		return fmt.Errorf("%w: %s reads the SNI extent", ErrNeedSNI, s.Label())
	}
	if req&ReqHost != 0 && !m.HasHost() {
		return fmt.Errorf("%w: %s reads the HTTP Host header", ErrNeedHost, s.Label())
	}
	return nil
}

// Build compiles the strategy into a Plan for one first message. payload is
// copied, so the caller's buffer is never mutated by an op.
func (s Strategy) Build(payload []byte, m tlsmsg.Meta, have Cap, bud Budget) (Plan, error) {
	b := &Builder{
		Payload: append([]byte(nil), payload...),
		Meta:    m,
		Caps:    have,
		Budget:  bud.orDefault(),
	}
	return s.BuildWith(b)
}

// BuildWith runs the strategy over a builder the caller has configured — the
// way `dpb probe` gets Strict, where a downgrade must be an error rather than a
// quietly weaker plan scored under the original spec's name.
func (s Strategy) BuildWith(b *Builder) (Plan, error) {
	if b == nil {
		return Plan{}, fmt.Errorf("%w: nil builder", ErrBadValue)
	}
	if err := s.CheckAgainst(b.Caps, b.Meta); err != nil {
		return Plan{}, err
	}
	for _, st := range s.Steps {
		if err := st.Apply(b); err != nil {
			return Plan{}, fmt.Errorf("%s: %s: %w", s.Label(), st.Name(), err)
		}
	}
	return b.Build(s.Spec)
}
