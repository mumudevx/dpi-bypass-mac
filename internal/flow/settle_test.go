package flow_test

import (
	"context"
	"net"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// TestSettleDropsARungTheRelayProvedBroken is the measured Türk Telekom shape
// this package could not see before: the middlebox lets the origin's first
// segment through and resets immediately behind it.
//
// judge commits on that segment, so the walk scores the rung a win and caches
// it — and the handshake then dies without the client ever writing a byte. A
// TLS client that never writes again never completed the handshake, so the rung
// did not work, and the only place that fact exists is the relay.
//
// Measured against updates.discord.com on a TT line: plain reset before any
// response byte, tlsfrag:pos=snimid answered with exactly 1388 bytes and a
// reset, up=0. The verdict store then held "tlsfrag:pos=snimid succeeded" for a
// week and every later connection replayed the rung that breaks the handshake,
// which is what pinned Discord's updater to a -9816 loop.
func TestSettleDropsARungTheRelayProvedBroken(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "updates.discord.com")
	up1 := newScriptConn(step{err: resetErr()})
	up2 := newScriptConn(step{data: []byte("SERVERHELLO")})
	sd := &scriptDialer{conns: []net.Conn{up1, up2}}
	store := newMemStore()
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}
	tgt := flow.Target{Name: "updates.discord.com", Addr: testAddr, Port: 443}

	out, err := l.Run(context.Background(), tgt, watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	broken := out.Spec
	if broken == "" {
		t.Fatal("the walk did not escalate, so there is no committed rung to settle")
	}
	if v := store.get(t, tgt.Name); v.Source != policy.SrcLearnedDesync || v.Spec != broken {
		t.Fatalf("before settling, cached verdict = %s/%q, want learned-desync/%q",
			v.Source, v.Spec, broken)
	}

	// The relay finished: the client never wrote a byte, so the handshake this
	// rung was supposed to carry never completed.
	l.Settle(tgt, broken, m, 0)

	v := store.get(t, tgt.Name)
	if v.Spec == broken {
		t.Errorf("cached Spec is still %q; a rung the relay proved broken must not stay the winner", broken)
	}
	for _, s := range v.Ladder {
		if s == broken {
			t.Errorf("ladder still offers %q: the next walk would spend an attempt on the broken rung (ladder %q)",
				broken, v.Ladder)
		}
	}
	// The pruning is only worth anything if the engine still hands this record
	// back. policy.Engine.cached drops SrcDefault on the floor, so demoting the
	// source here would throw the pruned ladder away with it.
	if v.Source != policy.SrcLearnedDesync {
		t.Errorf("source = %s, want learned-desync so Engine.cached keeps the pruned ladder", v.Source)
	}
}

// TestSettleReachesTheNextRungOnTheFollowingWalk is the payoff. Pruning the
// ladder is only worth doing if the record survives policy.Engine and the next
// walk spends its attempts on rungs that have not already been disproved, so
// this drives the real engine rather than restating cached()'s transformation.
func TestSettleReachesTheNextRungOnTheFollowingWalk(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "updates.discord.com")
	store := newMemStore()
	tgt := flow.Target{Name: "updates.discord.com", Addr: testAddr, Port: 443}
	specs, ok := strategy.LadderSpecs("tr")
	if !ok {
		t.Fatal("the tr ladder is missing from this build")
	}
	eng := policy.NewEngine(policy.EngineOptions{
		Store: store, InspectPorts: []int{443}, Ladder: specs,
	})

	// Walk one: plain is reset, the second rung commits on a forwarded segment.
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}),
		newScriptConn(step{data: []byte("SERVERHELLO")}),
	}}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}
	out, err := l.Run(context.Background(), tgt, eng.ForName(tgt.Name, tgt.Port), h, m, nil)
	if err != nil {
		t.Fatalf("first walk: %v", err)
	}
	broken := out.Spec
	if broken == "" {
		t.Fatal("the first walk did not escalate, so there is no committed rung to settle")
	}
	l.Settle(tgt, broken, m, 0)

	// Walk two, through the engine exactly as a front end would ask.
	sd2 := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}),
		newScriptConn(step{err: resetErr()}),
		newScriptConn(step{data: []byte("SERVERHELLO")}),
	}}
	l2 := &flow.LadderRunner{Dial: sd2, Store: store, RTT: flow.NewRTTTracker()}
	out2, err := l2.Run(context.Background(), tgt, eng.ForName(tgt.Name, tgt.Port), h, m, nil)
	if err != nil {
		t.Fatalf("second walk: %v", err)
	}
	for _, s := range specsOf(out2.Attempts) {
		if s == broken {
			t.Fatalf("the second walk tried %q again; attempts %q", broken, specsOf(out2.Attempts))
		}
	}
	if out2.Spec == "" || out2.Spec == broken {
		t.Fatalf("second walk won with %q, want a rung past %q", out2.Spec, broken)
	}
}

// TestSettleLeavesAWorkingFlowAlone: a client that wrote is a handshake that
// completed. The rung worked and the cache must keep it, or every long-lived
// connection would demote its own winner on the way out.
func TestSettleLeavesAWorkingFlowAlone(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}),
		newScriptConn(step{data: []byte("SERVERHELLO")}),
	}}
	store := newMemStore()
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}
	tgt := flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}

	out, err := l.Run(context.Background(), tgt, watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	before := store.get(t, tgt.Name)

	l.Settle(tgt, out.Spec, m, 1)

	after := store.get(t, tgt.Name)
	if after.Spec != before.Spec || after.Source != before.Source {
		t.Errorf("a flow that carried %d client byte(s) was demoted: %s/%q became %s/%q",
			1, before.Source, before.Spec, after.Source, after.Spec)
	}
}

// TestSettleNeverDemotesLearnedPlain pins the fragile-host guarantee.
// MEASUREMENTS.md §5.1 measured every bypassing emitter breaking Turkish
// banking, and §5.2 step 4 asks that such a host be desynced at most once ever.
// A learned-plain verdict is what delivers that, so nothing here may reopen it:
// a bank whose connection is reset mid-stream must stay direct.
func TestSettleNeverDemotesLearnedPlain(t *testing.T) {
	t.Parallel()
	_, m := hello(t, "isbank.com.tr")
	store := newMemStore()
	tgt := flow.Target{Name: "isbank.com.tr", Addr: testAddr, Port: 443}
	plain := policy.Verdict{
		Class:  policy.ScopeDirect,
		Source: policy.SrcLearnedPlain,
		Reason: "plain succeeded; not desynced",
	}
	if err := store.Put(policy.NetworkID{}, tgt.Name, plain); err != nil {
		t.Fatal(err)
	}
	l := &flow.LadderRunner{Dial: &scriptDialer{}, Store: store, RTT: flow.NewRTTTracker()}

	// Whatever the relay saw, and whatever rung is named, a learned-plain
	// record is not this function's to touch.
	l.Settle(tgt, "tlsfrag:pos=snimid", m, 0)
	l.Settle(tgt, "", m, 0)

	got := store.get(t, tgt.Name)
	if got.Source != policy.SrcLearnedPlain || got.Class != policy.ScopeDirect {
		t.Fatalf("learned-plain verdict became %s/%s; a fragile host must stay direct", got.Source, got.Class)
	}
}

// TestSettleCorrectsAProbedRung: a probe is a measurement, and a relay that
// carried no client byte is a later measurement of the same thing. forget() and
// recordLoss() both rewrite SrcProbed for exactly that reason, so this must too
// — otherwise `dpb probe` could pin a host to a rung the relay disproves on
// every connection.
func TestSettleCorrectsAProbedRung(t *testing.T) {
	t.Parallel()
	_, m := hello(t, "cdn.discordapp.com")
	store := newMemStore()
	tgt := flow.Target{Name: "cdn.discordapp.com", Addr: testAddr, Port: 443}
	probed := policy.Verdict{
		Class:  policy.ScopeDesync,
		Spec:   "tlsfrag:pos=snimid",
		Ladder: []string{"", "tlsfrag:pos=snimid", "oob:pos=1"},
		Source: policy.SrcProbed,
		Reason: "probed",
	}
	if err := store.Put(policy.NetworkID{}, tgt.Name, probed); err != nil {
		t.Fatal(err)
	}
	l := &flow.LadderRunner{Dial: &scriptDialer{}, Store: store, RTT: flow.NewRTTTracker()}

	l.Settle(tgt, probed.Spec, m, 0)

	got := store.get(t, tgt.Name)
	for _, s := range got.Ladder {
		if s == probed.Spec {
			t.Fatalf("ladder still offers the disproved probed rung %q: %q", probed.Spec, got.Ladder)
		}
	}
}
