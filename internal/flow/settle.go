package flow

import (
	"fmt"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// Settle reconsiders what the walk cached, once the relay for that connection
// has finished. It is the second half of the evidence guard, and it exists
// because the first half cannot see far enough.
//
// judge commits on the first upstream byte, and rejects() weighs that byte
// against the rung. Both run before the handshake has had a chance to finish,
// so neither can see the shape MEASUREMENTS.md §1 describes from the other
// side: the middlebox forwards the origin's first segment and puts a reset
// behind it. The bytes are real, they are not an alert, and they are not from a
// sinkhole — rejects() has nothing to object to — and the rung is cached as a
// winner for a week on a handshake that never completed.
//
// up is the client-to-upstream byte count the relay moved, NOT counting the
// first message the ladder sent itself. For TLS that number is the whole
// argument: a client cannot produce its Finished without a complete server
// flight, so a TLS flow that ended with the client having written nothing is a
// handshake that failed, whoever tore it down. Being wrong here costs one
// re-walk; being wrong the other way is a host that stays broken for a week.
//
// Measured: updates.discord.com on a TT line answers tlsfrag:pos=snimid with
// exactly 1388 bytes and a reset, up=0, and Discord's updater reports -9816
// (errSSLClosedNoNotify) in a retry loop. Forcing the rung out of the ladder
// reaches oob:pos=1, which completes the same handshake.
func (l *LadderRunner) Settle(t Target, spec string, m tlsmsg.Meta, up int64) {
	// A plain rung has nothing to demote to: it is already the bottom of every
	// ladder, and a learned-plain verdict is the fragile-host guarantee
	// MEASUREMENTS.md §5.2 step 4 asks for. Only a desync rung claimed to work
	// here, so only a desync rung can be wrong here.
	if spec == "" || up != 0 {
		return
	}
	if m.Proto != tlsmsg.ProtoTLS {
		// The argument above is about TLS. A plaintext client that sends one
		// request and never writes again is doing nothing unusual.
		return
	}
	if l.Store == nil || t.storeKey() == "" {
		return
	}
	prev, ok := l.Store.Get(l.netID(), t.storeKey())
	if !ok || prev.Spec != spec {
		// Something else has already rewritten this record — a later walk, or
		// forget() acting on an alert. It is not ours to second-guess.
		return
	}
	// The same set forget() and recordLoss() rewrite: an observation may
	// correct another observation. A rule is a decision about this host rather
	// than a measurement of it, and no relay gets to overrule one.
	switch prev.Source {
	case policy.SrcLearnedDesync, policy.SrcProbed:
	default:
		return
	}

	nv := prev
	nv.Ladder = withoutSpec(prev.Ladder, spec)
	nv.Spec = ""
	nv.Wins = 0
	nv.Losses = prev.Losses + 1
	nv.Learned = l.now()

	if !hasDesyncRung(nv.Ladder) {
		// Every rung this host had is gone. Drop the record to the source
		// policy.Engine ignores so the next connection re-walks from plain
		// against the full configured ladder, rather than inheriting an empty
		// one that can never escalate.
		nv.Class = policy.ScopeWatch
		nv.Ladder = nil
		nv.Source = policy.SrcDefault
		nv.Expires = time.Time{}
		nv.Reason = fmt.Sprintf("every rung failed the relay, last %q: the handshake never completed", specName(spec))
		l.logf("flow: %s: %q was the last rung and the relay proved it broken; re-walking from plain next time", t, specName(spec))
		l.put(t, prev, nv)
		return
	}

	// Source stays learned-desync on purpose. policy.Engine.cached returns
	// nothing for SrcDefault, so demoting it here would throw the pruned ladder
	// away with the verdict and the next walk would try the broken rung again.
	// Spec is cleared instead: this host still needs a desync, we no longer
	// claim to know which one, and rungs() puts plain first for an empty Spec.
	nv.Class = policy.ScopeDesync
	nv.Source = policy.SrcLearnedDesync
	nv.Expires = l.now().Add(LearnedDesyncTTL)
	nv.Reason = fmt.Sprintf("%q committed but the client never wrote: the handshake never completed, so the rung is dropped", specName(spec))
	l.logf("flow: %s: %q committed and the relay carried no client byte; dropping it from the ladder (%q left)",
		t, specName(spec), nv.Ladder)
	l.put(t, prev, nv)
}

// withoutSpec copies specs with one rung removed.
func withoutSpec(specs []string, drop string) []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

// hasDesyncRung reports whether specs still contain something to escalate TO.
// Plain is not one: it is what the walk starts with.
func hasDesyncRung(specs []string) bool {
	for _, s := range specs {
		if s != "" {
			return true
		}
	}
	return false
}
