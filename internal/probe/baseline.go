package probe

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// baselineRetries is how many times a target whose benign-SNI control was not
// clean is measured again before its result is called ambiguous. One retry: a
// lossy path is the common cause and it is usually not persistent, while a
// second retry buys little and costs two more dials per target.
const baselineRetries = 1

// Baseline decides which targets are actually blocked on this line.
//
// Every target is dialled by PINNED ADDRESS, never by hostname.
// MEASUREMENTS.md §5.4 records the first run of the compatibility matrix
// scoring every emitter 0/6 because Go's resolver answered every blocked name
// with the BTK sinkhole, so every emitter was measured against a blackhole
// rather than against the origin.
//
// Each target gets §1's experiment, which is the only one that isolates the
// SNI from every routing variable: the SAME address is dialled twice, once
// with a benign hostname and once with the real one.
//
//   - benign 0/N  → the path is unreachable regardless of what we claim to be
//     talking to. ShapeIPBlock: no desync can help, so stop.
//   - benign N/N and real 0/N → SNI-keyed blocking. This is a target.
//   - anything else → not blocked here, or too lossy to tell, and in both cases
//     it must be dropped rather than measured. A prober that scores a target it
//     could not establish as blocked will happily "fix" it with a random
//     emitter and report a winner that won nothing.
func (r *Runner) Baseline(ctx context.Context) ([]Target, []Target, error) {
	plain, err := r.o.Registry.Get("")
	if err != nil {
		return nil, nil, fmt.Errorf("probe: the plain strategy is not available: %w", err)
	}

	var (
		blocked    []Target
		notBlocked []Target
		ipBlocked  []Target
		rsts       []time.Duration
		candidates int
	)

	for _, t := range r.o.Targets {
		if t.Kind != TargetBlocked {
			continue
		}
		candidates++
		t = r.pin(ctx, t)

		verdict, latencies := r.baselineOne(ctx, plain, t)
		rsts = append(rsts, latencies...)
		switch verdict {
		case baselineIPBlock:
			ipBlocked = append(ipBlocked, t)
			r.warn("%s is unreachable even with a benign SNI: the block is at the IP layer here, "+
				"and no packet strategy can help (MEASUREMENTS.md §1's control experiment)", t)
		case baselineBlocked:
			blocked = append(blocked, t)
		default:
			notBlocked = append(notBlocked, t)
		}
	}

	sortTargets(blocked)
	sortTargets(notBlocked)
	r.blocked = blocked
	r.notBlocked = notBlocked
	r.rstLatency = medianDuration(rsts)

	switch {
	case candidates > 0 && len(ipBlocked) == candidates:
		r.shape = ShapeIPBlock
		return blocked, notBlocked, fmt.Errorf("%w: %d of %d targets",
			ErrIPBlock, len(ipBlocked), candidates)
	case len(blocked) == 0:
		r.shape = ShapeClean
		if r.dnsPoisoned() {
			// The names are answered with a censor's address but the paths
			// themselves are clean. A packet strategy is the wrong instrument
			// for that and the resolver chain is the right one.
			r.shape = ShapeDNSOnly
		}
	default:
		r.shape = ShapeSNIReset
		if r.dnsPoisoned() {
			r.shape = ShapeSNIResetAndDNS
		}
	}
	return blocked, notBlocked, nil
}

type baselineVerdict uint8

const (
	baselineNotBlocked baselineVerdict = iota
	baselineBlocked
	baselineIPBlock
)

// baselineOne runs §1's two-dial experiment against one target.
//
// The two dials go to the SAME pinned address on the SAME port and differ only
// in the hostname sent as the SNI. That is the whole experiment: "same IP, same
// port, same TCP handshake. Only the SNI differs."
func (r *Runner) baselineOne(ctx context.Context, plain strategy.Strategy, t Target) (baselineVerdict, []time.Duration) {
	reps := min(max(r.reps(), 2), 3)
	benign, haveControl := r.benignFor(t)

	for attempt := 0; ; attempt++ {
		var bPass, bTotal int
		if haveControl {
			bPass, bTotal = tallyReach(r.attempts(ctx, plain, benign, reps))
		}
		actual := r.attempts(ctx, plain, t, reps)
		rPass, rTotal := tallyReach(actual)
		lat := resetLatencies(actual)

		switch {
		case bTotal >= 2 && bPass == 0:
			return baselineIPBlock, lat

		case !haveControl:
			// No benign control to compare against, so the only available
			// evidence is that every plain attempt failed. Weaker than §1's
			// experiment, and the warning in pin already said why.
			if rTotal >= 2 && rPass == 0 {
				return baselineBlocked, lat
			}
			return baselineNotBlocked, lat

		case bPass == bTotal && rTotal >= 2 && rPass == 0:
			return baselineBlocked, lat

		case bPass < bTotal && attempt < baselineRetries:
			// The benign control itself lost attempts, so this round cannot
			// separate "blocked" from "lossy". Retry rather than score it —
			// the same hygiene the sweep applies to a round whose control was
			// down, applied to the phase that decides what gets swept.
			r.logf("probe: baseline: retrying %s: the benign control was %d/%d", t, bPass, bTotal)
			continue
		}

		if bPass < bTotal {
			r.warn("the path to %s is lossy: the benign-SNI control passed only %d of %d attempts, "+
				"so %s cannot be established as blocked and was dropped from the target set",
				t.Addr, bPass, bTotal, t.Host)
		} else if rPass < rTotal {
			r.warn("%s passed %d of %d plain attempts, which is neither reachable nor blocked; "+
				"it was dropped rather than measured", t, rPass, rTotal)
		}
		return baselineNotBlocked, lat
	}
}

// benignFor builds §1's control dial: the control hostname aimed at THIS
// target's address and port.
func (r *Runner) benignFor(t Target) (Target, bool) {
	if len(r.controls) == 0 || t.Addr == "" {
		return Target{}, false
	}
	return Target{
		Host: r.controls[0].Host,
		Port: t.DialPort(),
		Kind: TargetControl,
		Addr: t.Addr,
	}, true
}

// resetLatencies is how long the censor took to answer, for the trials where it
// answered with a reset. MEASUREMENTS.md §6 measures ~22 ms on this line, which
// is what tells an injected RST from an origin that is simply down.
func resetLatencies(ts []Trial) []time.Duration {
	var out []time.Duration
	for _, t := range ts {
		if t.Verdict == VerdictReset && t.Latency > 0 {
			out = append(out, t.Latency)
		}
	}
	return out
}

func (r *Runner) dnsPoisoned() bool {
	for _, h := range r.dns {
		if h.Signal.Sinkhole || h.Signal.Poisoned {
			return true
		}
	}
	return false
}

// pin resolves an unpinned target through the tool's own chain and records the
// address on the target.
//
// A target that stays unpinned is measured through the chain on every dial,
// which is correct but costs a query per attempt and makes §1's experiment
// impossible: the benign-SNI control would reach a different address, so a
// failure could be routing rather than SNI. The warning says so.
func (r *Runner) pin(ctx context.Context, t Target) Target {
	if t.Addr != "" || r.o.Chain == nil {
		if t.Addr == "" {
			r.warn("%s has no pinned address and no resolver chain is configured, so the "+
				"benign-SNI control cannot be aimed at the same address (MEASUREMENTS.md §1)", t.Host)
		}
		return t
	}
	addrs, err := r.o.Chain.Resolve(ctx, t.Host)
	if err != nil || len(addrs) == 0 {
		r.warn("%s could not be resolved through the chain (%v), so it was left unpinned", t.Host, err)
		return t
	}
	a := pickAddr(addrs, r.sinkholes())
	if !a.IsValid() {
		r.warn("%s resolved only to known censorship addresses, so it was left unpinned "+
			"(MEASUREMENTS.md §2)", t.Host)
		return t
	}
	t.Addr = a.String()
	r.logf("probe: pinned %s to %s", t.Host, t.Addr)
	return t
}

// pickAddr takes the first address that is not a censorship answer. The chain
// already returns IPv4 first when both families answer, which is the family
// this tool has measured end to end.
func pickAddr(addrs []netip.Addr, sinks []netip.Addr) netip.Addr {
	for _, a := range addrs {
		if !isSinkhole(a, sinks) {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}
