package flow_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"net/netip"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/ops"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/testcensor"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// hello returns a captured ClientHello and its parse, which is what a front end
// hands the ladder.
func hello(t *testing.T, name string) ([]byte, tlsmsg.Meta) {
	t.Helper()
	h := clientHello(t, name)
	m := tlsmsg.Parse(h, 443)
	if !m.Complete || !m.HasSNI() {
		t.Fatalf("captured hello for %q is not a complete hello with an SNI: %+v", name, m)
	}
	return h, m
}

// TestLadderTT2026Escalates is the headline claim, restated as an executable
// assertion against the measured middlebox model.
//
// MEASUREMENTS.md §3.2 (the record rule), §5.2 (plain first) and §6 (18/18
// immediate retries): a blocked name costs exactly two attempts — plain, then
// tlsfrag:pos=snimid — succeeds on the second, and caches the winner.
func TestLadderTT2026Escalates(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	origin := rawOrigin(t, []byte("SERVERHELLO"))
	box := testcensor.New(testcensor.TT2026(), testcensor.Options{Port: 443})
	dial := &boxDialer{box: box, addr: origin}
	store := newMemStore()

	l := &flow.LadderRunner{Dial: dial, Store: store, RTT: flow.NewRTTTracker()}
	tgt := flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}

	out, err := l.Run(context.Background(), tgt, watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v (attempts %v)", err, specsOf(out.Attempts))
	}

	if got := specsOf(out.Attempts); len(got) != 2 || got[0] != "" || got[1] != "tlsfrag:pos=snimid" {
		t.Fatalf("attempts = %q, want [plain tlsfrag:pos=snimid]", got)
	}
	if out.Attempts[0].Class != flow.FailResetBeforeResponse {
		t.Errorf("attempt 1 class = %s, want %s", out.Attempts[0].Class, flow.FailResetBeforeResponse)
	}
	if out.Spec != "tlsfrag:pos=snimid" {
		t.Errorf("winning spec = %q, want tlsfrag:pos=snimid", out.Spec)
	}
	if string(out.Pre) != "SERVERHELLO" {
		t.Errorf("Pre = %q, want the upstream greeting; a hole here is a hole in the client's stream", out.Pre)
	}

	v := store.get(t, "discord.com")
	if v.Source != policy.SrcLearnedDesync {
		t.Errorf("cached source = %s, want SrcLearnedDesync", v.Source)
	}
	if v.Class != policy.ScopeDesync || v.Spec != "tlsfrag:pos=snimid" {
		t.Errorf("cached verdict = %s/%q, want desync/tlsfrag:pos=snimid", v.Class, v.Spec)
	}
	if v.Expires.IsZero() {
		t.Error("a learned desync must expire; MEASUREMENTS.md §4 records that TR DPI configuration rots")
	}

	// The middlebox records a flow when the connection closes.
	if err := out.Conn.Close(); err != nil {
		t.Fatalf("close the winning connection: %v", err)
	}
	flows := box.Flows()
	if len(flows) != 2 {
		t.Fatalf("middlebox saw %d flows, want 2", len(flows))
	}
	if !flows[0].Verdict.Blocked() {
		t.Errorf("flow 1 (plain) was not blocked by TT2026: %s", flows[0].Verdict)
	}
	if flows[1].Verdict.Blocked() {
		t.Errorf("flow 2 (tlsfrag) was blocked: %s", flows[1].Verdict)
	}
}

// TestLadderFragileNeverEscalates is the other half of the architecture, and the
// one that decides it. MEASUREMENTS.md §5: 10 of 41 Turkish hosts — every bank
// and every .gov.tr tested — break under record splitting. They must succeed on
// attempt one and be recorded as plain-forever.
func TestLadderFragileNeverEscalates(t *testing.T) {
	t.Parallel()
	for _, model := range []testcensor.Model{testcensor.Fragile(), testcensor.FragileEOF(), testcensor.FragileReset()} {
		t.Run(model.Name, func(t *testing.T) {
			t.Parallel()
			h, m := hello(t, "www.yapikredi.com.tr")
			origin := rawOrigin(t, []byte("SERVERHELLO"))
			box := testcensor.New(model, testcensor.Options{Port: 443})
			dial := &boxDialer{box: box, addr: origin}
			store := newMemStore()

			l := &flow.LadderRunner{Dial: dial, Store: store, RTT: flow.NewRTTTracker()}
			tgt := flow.Target{Name: "www.yapikredi.com.tr", Addr: testAddr, Port: 443}

			out, err := l.Run(context.Background(), tgt, watchVerdict(), h, m, nil)
			if err != nil {
				t.Fatalf("Run: %v (attempts %v)", err, specsOf(out.Attempts))
			}
			defer out.Conn.Close()

			if out.Escalations() != 0 {
				t.Fatalf("escalated %d time(s) on a host that works plain: %q", out.Escalations(), specsOf(out.Attempts))
			}
			if out.Spec != "" {
				t.Errorf("winning spec = %q, want plain", out.Spec)
			}
			if dial.count() != 1 {
				t.Errorf("dialled %d times, want 1", dial.count())
			}

			v := store.get(t, "www.yapikredi.com.tr")
			if v.Source != policy.SrcLearnedPlain || v.Class != policy.ScopeDirect {
				t.Errorf("cached verdict = %s/%s, want direct/SrcLearnedPlain", v.Class, v.Source)
			}
			// Durably, but not forever. §5.2 step 4 asks that a bank be
			// desynced at most once per re-test window; a zero Expires would
			// make the verdict immortal, and because policy rewrites
			// SrcLearnedPlain to ScopeDirect the ladder would never be invoked
			// for this host again to notice it had gone wrong.
			if v.Expires.IsZero() {
				t.Error("a learned-plain verdict with no expiry can never be re-tested: " +
					"policy relays SrcLearnedPlain as ScopeDirect and the ladder is never invoked again")
			}
		})
	}
}

// TestLadderCommitGuardBlocksRetry is the guard itself. One upstream byte has
// reached us, so the reset that follows is the origin's problem to report and
// never ours to retry: a retry would replay bytes the client has already seen.
func TestLadderCommitGuardBlocksRetry(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "example.com")
	up := newScriptConn(
		step{data: []byte("HTTP/1.1 200")},
		step{err: resetErr()},
	)
	sd := &scriptDialer{conns: []net.Conn{up}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	tgt := flow.Target{Name: "example.com", Addr: testAddr, Port: 443}

	out, err := l.Run(context.Background(), tgt, watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Attempts) != 1 {
		t.Fatalf("attempts = %q, want exactly one: the connection was committed", specsOf(out.Attempts))
	}
	if sd.count() != 1 {
		t.Fatalf("dialled %d times after commit, want 1", sd.count())
	}

	// The reset is now the relay's to surface, and it must be visible.
	buf := make([]byte, 16)
	if _, err := out.Conn.Read(buf); err == nil {
		t.Fatal("the post-commit reset was swallowed; the client must see the error")
	} else if !testcensor.IsReset(err) {
		t.Fatalf("post-commit error = %v, want a reset", err)
	}
	if got := flow.Classify(resetErr(), true); got != flow.FailResetAfterResponse || got.Retryable() {
		t.Fatalf("Classify(reset, committed) = %s (retryable %v), want reset-after-response and not retryable", got, got.Retryable())
	}
}

// TestLadderExhaustion asserts we never fall back to "send it plain and call it
// success". Every rung failing is an attributable error, not a silent leak of an
// unmodified ClientHello.
func TestLadderExhaustion(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	var conns []net.Conn
	for i := 0; i < 6; i++ {
		conns = append(conns, newScriptConn(step{err: resetErr()}))
	}
	sd := &scriptDialer{conns: conns}
	store := newMemStore()
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}

	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if !errors.Is(err, flow.ErrLadderExhausted) {
		t.Fatalf("err = %v, want ErrLadderExhausted", err)
	}
	if out.Conn != nil {
		t.Fatal("a failed walk must not hand back a connection")
	}
	// Pinning this to DefaultMaxAttempts made the assertion a restatement of a
	// constant: it broke when the ladder legitimately lost a rung, and it would
	// have stayed green if the walk had silently stopped early on a ladder
	// longer than the budget. The contract is that a failed walk tries every
	// rung it is allowed to.
	rungs, err := strategy.Ladder("tr")
	if err != nil {
		t.Fatal(err)
	}
	want := len(rungs)
	if want > flow.DefaultMaxAttempts {
		want = flow.DefaultMaxAttempts
	}
	if len(out.Attempts) != want {
		t.Fatalf("attempts = %d, want %d (the TR ladder has %d rungs, budget %d)",
			len(out.Attempts), want, len(rungs), flow.DefaultMaxAttempts)
	}
	for i, a := range out.Attempts {
		if i > 0 && a.Spec == "" {
			t.Errorf("attempt %d re-sent the hello plain: an exhausted walk must never leak it", i+1)
		}
	}
	if _, ok := store.Get(policy.NetworkID{}, "discord.com"); ok {
		t.Error("a walk where nothing worked must not cache a winner")
	}
}

// TestLadderCachedDesyncIsAppliedFirst: a cached winner costs one attempt, not a
// re-walk. §5.2 step 3.
func TestLadderCachedDesyncIsAppliedFirst(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	origin := rawOrigin(t, []byte("SERVERHELLO"))
	box := testcensor.New(testcensor.TT2026(), testcensor.Options{Port: 443})
	dial := &boxDialer{box: box, addr: origin}
	store := newMemStore()
	l := &flow.LadderRunner{Dial: dial, Store: store, RTT: flow.NewRTTTracker()}

	v := watchVerdict()
	v.Class = policy.ScopeDesync
	v.Spec = "tlsfrag:pos=snimid"
	v.Source = policy.SrcLearnedDesync
	v.Wins = 1

	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}, v, h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if len(out.Attempts) != 1 || out.Attempts[0].Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("attempts = %q, want the cached spec applied on attempt one", specsOf(out.Attempts))
	}
	if got := store.get(t, "discord.com").Wins; got != 2 {
		t.Errorf("Wins = %d, want 2 (the cached winner won again)", got)
	}
}

// TestLadderDemotesAFailedCachedWinner: when the cached winner stops working,
// the store is told, so three consecutive losses reset the host to unknown.
func TestLadderDemotesAFailedCachedWinner(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	var conns []net.Conn
	for i := 0; i < 8; i++ {
		conns = append(conns, newScriptConn(step{err: resetErr()}))
	}
	sd := &scriptDialer{conns: conns}
	store := newMemStore()
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}

	v := watchVerdict()
	v.Class = policy.ScopeDesync
	v.Spec = "tlsfrag:pos=snimid"
	v.Source = policy.SrcLearnedDesync

	if _, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}, v, h, m, nil); err == nil {
		t.Fatal("want an error when every rung fails")
	}
	if len(store.demoted) != 1 {
		t.Fatalf("demoted %v, want exactly one demotion of the cached winner", store.demoted)
	}
}

// TestLadderBypassIsNeverEscalated: ScopeBypass is a hard veto. One plain
// attempt, no desync, ever — that is what makes a --bypass rule a promise.
func TestLadderBypassIsNeverEscalated(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "www.isbank.com.tr")
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{err: resetErr()})}}
	store := newMemStore()
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}

	v := policy.Verdict{Class: policy.ScopeBypass, Source: policy.SrcUserBypass}
	out, err := l.Run(context.Background(), flow.Target{Name: "www.isbank.com.tr", Addr: testAddr, Port: 443}, v, h, m, nil)
	if err == nil {
		t.Fatal("want the failure surfaced, not a desync")
	}
	if len(out.Attempts) != 1 {
		t.Fatalf("attempts = %q, want exactly one plain attempt", specsOf(out.Attempts))
	}
	if sd.count() != 1 {
		t.Fatalf("dialled %d times for a bypassed host, want 1", sd.count())
	}
	if store.puts != 0 {
		t.Errorf("a bypass verdict was overwritten by a learned one (%d puts)", store.puts)
	}
}

// TestLadderNonIdempotentRequestIsNeverReplayed: a buffered POST may not be
// re-sent on a fresh connection, because the origin may already have acted on it.
func TestLadderNonIdempotentRequestIsNeverReplayed(t *testing.T) {
	t.Parallel()
	post := []byte("POST /pay HTTP/1.1\r\nHost: bank.example\r\nContent-Length: 3\r\n\r\nabc")
	m := tlsmsg.Parse(post, 80)
	if m.Proto != tlsmsg.ProtoHTTP {
		t.Fatalf("fixture did not parse as HTTP: %+v", m)
	}
	if flow.Replayable(post, m) {
		t.Fatal("a POST with a body is not replayable")
	}

	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}),
		newScriptConn(step{data: []byte("HTTP/1.1 200 OK")}),
	}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	v := watchVerdict()

	out, err := l.Run(context.Background(), flow.Target{Name: "bank.example", Addr: testAddr, Port: 80}, v, post, m, nil)
	if err == nil {
		t.Fatal("want an error rather than a replayed POST")
	}
	if len(out.Attempts) != 2 || out.Attempts[1].Class != flow.FailNotReplayable {
		t.Fatalf("attempts = %v, want the second to stop with not-replayable", out.Attempts)
	}
	if sd.count() != 1 {
		t.Fatalf("dialled %d times; the POST must never reach a second upstream connection", sd.count())
	}
}

// TestLadderIdempotentRequestIsReplayed is the companion: a GET with no body may
// be retried, so plaintext HTTP is not excluded from the ladder wholesale.
func TestLadderIdempotentRequestIsReplayed(t *testing.T) {
	t.Parallel()
	get := []byte("GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n")
	m := tlsmsg.Parse(get, 80)
	if !flow.Replayable(get, m) {
		t.Fatal("a bodyless GET is replayable")
	}
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}),
		newScriptConn(step{data: []byte("HTTP/1.1 200 OK")}),
	}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	v := watchVerdict()
	v.Ladder = []string{"", "hostcase"}

	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 80}, v, get, m, nil)
	if err != nil {
		t.Fatalf("Run: %v (attempts %v)", err, specsOf(out.Attempts))
	}
	defer out.Conn.Close()
	if out.Spec != "hostcase" {
		t.Fatalf("winning spec = %q, want hostcase", out.Spec)
	}
}

// TestLadderPlainIsAlwaysFirst: a configured ladder that forgets plain does not
// get to skip it. MEASUREMENTS.md §5.2 step 1 is a correctness requirement.
func TestLadderPlainIsAlwaysFirst(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "www.akbank.com")
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{data: []byte("SERVERHELLO")})}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	v := policy.Verdict{Class: policy.ScopeWatch, Ladder: []string{"tlsfrag:pos=snimid", "oob:pos=1"}}

	out, err := l.Run(context.Background(), flow.Target{Name: "www.akbank.com", Addr: testAddr, Port: 443}, v, h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if out.Spec != "" {
		t.Fatalf("winning spec = %q, want plain: the first rung must be undesynced", out.Spec)
	}
	if got := sd.conns[0].(*scriptConn).stream(); string(got) != string(h) {
		t.Fatalf("attempt one modified the first message (%d bytes vs %d)", len(got), len(h))
	}
}

// TestLadderDialFailureIsNotALadderFailure: a path that will not carry a TCP
// connection at all is reported as ErrNoUpstream, because no rung can fix it.
func TestLadderDialFailureIsNotALadderFailure(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	sd := &scriptDialer{errs: []error{
		errors.New("dial 1"), errors.New("dial 2"), errors.New("dial 3"),
		errors.New("dial 4"), errors.New("dial 5"),
	}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if !errors.Is(err, flow.ErrNoUpstream) {
		t.Fatalf("err = %v, want ErrNoUpstream", err)
	}
	for i, a := range out.Attempts {
		if a.Class != flow.FailDial {
			t.Errorf("attempt %d class = %s, want dial", i, a.Class)
		}
	}
}

// TestLadderSilenceFromAnUnknownDestinationDoesNotDesync is the timeout policy.
// On an unmeasured destination, silence is indistinguishable from a slow link,
// and desyncing on it would break fragile hosts on no evidence — the one
// outcome MEASUREMENTS.md §5.1 forbids.
func TestLadderSilenceFromAnUnknownDestinationDoesNotDesync(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "slow.example")
	// The origin answers well after the 300 ms minimum window but well inside
	// the 2 s an unmeasured destination is given.
	up := newScriptConn(step{delay: 350 * time.Millisecond, data: []byte("SERVERHELLO")})
	sd := &scriptDialer{conns: []net.Conn{up}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}

	out, err := l.Run(context.Background(), flow.Target{Name: "slow.example", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if out.Escalations() != 0 {
		t.Fatalf("a slow but working origin was escalated %d time(s)", out.Escalations())
	}
	if string(out.Pre) != "SERVERHELLO" {
		t.Fatalf("Pre = %q, want the late greeting", out.Pre)
	}
}

// TestLadderSilenceFromAMeasuredDestinationDoesEscalate is the other side: once
// the destination has answered before, silence is evidence.
func TestLadderSilenceFromAMeasuredDestinationDoesEscalate(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "dropped.example")
	rtt := flow.NewRTTTracker()
	rtt.Observe(testAddr.Addr(), 5*time.Millisecond) // measured fast before

	silent := newScriptConn() // never answers
	answer := newScriptConn(step{data: []byte("SERVERHELLO")})
	sd := &scriptDialer{conns: []net.Conn{silent, answer}}
	l := &flow.LadderRunner{Dial: sd, RTT: rtt}

	out, err := l.Run(context.Background(), flow.Target{Name: "dropped.example", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if len(out.Attempts) != 2 {
		t.Fatalf("attempts = %q, want a plain attempt and one escalation", specsOf(out.Attempts))
	}
	if out.Attempts[0].Class != flow.FailTimeoutBeforeResponse {
		t.Fatalf("attempt 1 class = %s, want timeout-before-response", out.Attempts[0].Class)
	}
}

// TestSingleflightCollapsesParallelConnections: the six connections a browser
// opens must walk the ladder once, not six times. Six independent walks are six
// independent chances to escalate a host where one walk settles on plain, and
// six times the retry traffic arriving at the middlebox at once.
func TestSingleflightCollapsesParallelConnections(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	origin := rawOrigin(t, []byte("SERVERHELLO"))
	box := testcensor.New(testcensor.TT2026(), testcensor.Options{Port: 443})
	dial := &boxDialer{box: box, addr: origin}
	store := newMemStore()
	l := &flow.LadderRunner{
		Dial: dial, Store: store, RTT: flow.NewRTTTracker(), Single: policy.NewSingleflight(),
	}
	tgt := flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}

	const n = 6
	var wg sync.WaitGroup
	outs := make([]flow.Outcome, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// A front end always consults the store before the ladder, so a
			// connection that arrives after the walk finished picks the winner
			// up from the cache rather than walking again.
			v := watchVerdict()
			if cached, ok := store.Get(policy.NetworkID{}, tgt.Name); ok {
				cached.Ladder = v.Ladder
				v = cached
			}
			outs[i], errs[i] = l.Run(context.Background(), tgt, v, h, m, nil)
		}(i)
	}
	close(start)
	wg.Wait()

	walks := 0
	for i := range outs {
		if errs[i] != nil {
			t.Fatalf("connection %d: %v", i, errs[i])
		}
		defer outs[i].Conn.Close()
		if outs[i].Escalations() > 0 {
			walks++
		}
	}
	if walks != 1 {
		t.Fatalf("%d of %d connections walked the ladder; it must be walked once per (network, host)", walks, n)
	}
	if dial.count() != n+1 {
		t.Errorf("dialled %d times, want %d (one blocked plain attempt, then one per connection)", dial.count(), n+1)
	}
}

// TestLadderTruncatedHelloIsNeverWalked is the §3.5 guard, restated as a ladder
// property. The previous implementation planned a record split against a prefix
// and silently degraded it into a 1-byte TCP split, which §3.1 measures at 0/5
// while it looks like a working strategy in the logs. Every rung that reads the
// record layer refuses an incomplete message BEFORE a socket is opened.
//
// The walk must then STOP rather than fall through to the rungs that have no
// message requirement: with a truncated hello the tr ladder collapses to
// [plain, oob:pos=1], and shipping the MSG_OOB junk byte — 0/20 on fragile
// hosts, §5.1 — is worse than reporting the failure. A hello we failed to read
// whole is also not evidence about the network: we truncated it ourselves.
func TestLadderTruncatedHelloIsNeverWalked(t *testing.T) {
	t.Parallel()
	h, _ := hello(t, "discord.com")
	part := h[:len(h)/2]
	m := tlsmsg.Parse(part, 443)
	m.Truncated = true
	if m.Complete {
		t.Fatal("fixture is not truncated")
	}
	if flow.Replayable(part, m) {
		t.Fatal("a prefix of a ClientHello must not be replayable on a fresh connection")
	}

	oob := newScriptConn(step{data: []byte("SERVERHELLO")})
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{err: resetErr()}), oob}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		watchVerdict(), part, m, nil)
	if err == nil {
		defer out.Conn.Close()
		t.Fatalf("winning spec = %q on a truncated hello; the walk must stop at plain", out.Spec)
	}
	if !errors.Is(err, flow.ErrLadderExhausted) {
		t.Fatalf("err = %v, want ErrLadderExhausted", err)
	}
	if sd.count() != 1 {
		t.Fatalf("dialled %d times, want 1: only plain may be sent for a message we could not read whole",
			sd.count())
	}
	if len(oob.oob) != 0 {
		t.Fatalf("%d urgent byte(s) reached an upstream on a truncated hello", len(oob.oob))
	}
	last := out.Attempts[len(out.Attempts)-1]
	if last.Class != flow.FailNotReplayable || last.Emitted {
		t.Fatalf("last attempt = %s emitted=%v, want a recorded, unemitted not-replayable rung",
			last.Class, last.Emitted)
	}
	if out.Escalations() != 0 {
		t.Fatalf("escalations = %d, want 0: one connection was opened", out.Escalations())
	}
}

// TestLadderReframingRungsRefuseAPrefix keeps the half of the old assertion
// that is still true and still worth pinning: the refusal is mechanical and
// happens before a socket is opened, with ErrNeedComplete naming the reason.
func TestLadderReframingRungsRefuseAPrefix(t *testing.T) {
	t.Parallel()
	h, _ := hello(t, "discord.com")
	part := h[:len(h)/2]
	m := tlsmsg.Parse(part, 443)
	m.Truncated = true

	for _, spec := range []string{"tlsfrag:pos=snimid", "chunk:size=12", "chunk:size=4"} {
		st, err := strategy.Parse(spec)
		if err != nil {
			t.Fatalf("parse %q: %v", spec, err)
		}
		if cerr := st.CheckAgainst(^strategy.Cap(0), m); !errors.Is(cerr, strategy.ErrNeedComplete) {
			t.Errorf("%q against a prefix = %v, want ErrNeedComplete", spec, cerr)
		}
	}
}

// TestLadderExtraBytesAreReplayedOnEveryRung: bytes the client sent after the
// first message must ride along on the retry, or the stream loses them.
func TestLadderExtraBytesAreReplayedOnEveryRung(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	extra := []byte("EXTRA")
	first := newScriptConn(step{err: resetErr()})
	second := newScriptConn(step{data: []byte("SERVERHELLO")})
	sd := &scriptDialer{conns: []net.Conn{first, second}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}

	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, extra)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	for i, c := range []*scriptConn{first, second} {
		if got := c.stream(); !strings.HasSuffix(string(got), "EXTRA") {
			t.Errorf("attempt %d did not replay the trailing client bytes", i+1)
		}
	}
}

// TestLadderNoDialer fails loudly rather than nil-dereferencing on a connection.
func TestLadderNoDialer(t *testing.T) {
	t.Parallel()
	l := &flow.LadderRunner{}
	if _, err := l.Run(context.Background(), flow.Target{Name: "x", Port: 443}, watchVerdict(), nil, tlsmsg.Meta{}, nil); err == nil {
		t.Fatal("want an error from a runner with no dialer")
	}
}

// TestLadderUnparseableRungStops: a ladder naming a spec this build cannot parse
// is a configuration defect and must not be walked past silently.
func TestLadderUnparseableRungStops(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}),
		newScriptConn(step{data: []byte("SERVERHELLO")}),
	}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	v := policy.Verdict{Class: policy.ScopeWatch, Ladder: []string{"", "nosuchop:x=1", "chunk:size=12"}}

	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}, v, h, m, nil)
	if err == nil {
		t.Fatalf("want an error; got spec %q", out.Spec)
	}
	if len(out.Attempts) != 2 || out.Attempts[1].Class != flow.FailBudget {
		t.Fatalf("attempts = %v, want the unparseable rung to stop the walk", out.Attempts)
	}
}

// TestLadderContextCancellationStopsTheWalk.
func TestLadderContextCancellationStopsTheWalk(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	var conns []net.Conn
	for i := 0; i < 6; i++ {
		conns = append(conns, newScriptConn(step{err: resetErr()}))
	}
	sd := &scriptDialer{conns: conns}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Run(ctx, flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil); err == nil {
		t.Fatal("want an error from a cancelled context")
	}
	if sd.count() != 0 {
		t.Fatalf("dialled %d times under a cancelled context, want 0", sd.count())
	}
}

// TestLadderRejectsAnUnknownTransport. A conn whose capabilities can only be
// guessed is a wiring defect, and guessing is how a profile ends up demanding
// root and then shipping the SNI unfragmented anyway.
func TestLadderRejectsAnUnknownTransport(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	sd := &scriptDialer{conns: []net.Conn{plainConn{}}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker()}
	_, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err == nil || !strings.Contains(err.Error(), "emit.Transport") {
		t.Fatalf("err = %v, want a message naming the missing transport", err)
	}
}

// TestLadderHonoursExplicitCapabilities: when the runner is told what the
// transport can do, a rung needing more is refused with a mechanical reason
// rather than quietly downgraded. That downgrade is how the previous
// implementation's flagship profile demanded root and shipped the SNI
// unfragmented anyway.
func TestLadderHonoursExplicitCapabilities(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{err: resetErr()})}}

	var (
		outcomes int
		logs     int
	)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	l := &flow.LadderRunner{
		Dial:     sd,
		Registry: ops.NewRegistry(),
		Caps:     strategy.CapStreamWrite | strategy.CapNoDelay, // no CapOOB
		Budget:   strategy.DefaultBudget(),
		NetID:    func() policy.NetworkID { return policy.NetworkID{Kind: "wifi", SSID: "test"} },
		Now:      func() time.Time { return now },
		RTT:      flow.NewRTTTracker(),
		OnOutcome: func(_ flow.Target, _ policy.Verdict, o flow.Outcome) {
			outcomes++
			if len(o.Attempts) == 0 {
				t.Error("OnOutcome fired with no attempts recorded")
			}
		},
		Logf: func(string, ...any) { logs++ },
	}
	v := policy.Verdict{Class: policy.ScopeWatch, Ladder: []string{"", "oob:pos=1"}}

	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}, v, h, m, nil)
	if err == nil {
		t.Fatal("want an error: the only escalation rung needs a capability the transport lacks")
	}
	if len(out.Attempts) != 2 || out.Attempts[1].Class != flow.FailBudget {
		t.Fatalf("attempts = %v, want the oob rung refused for want of a capability", out.Attempts)
	}
	if !errors.Is(out.Attempts[1].Err, strategy.ErrCapUnavailable) {
		t.Fatalf("oob was refused with %v, want ErrCapUnavailable", out.Attempts[1].Err)
	}
	if outcomes != 1 {
		t.Errorf("OnOutcome fired %d times, want 1", outcomes)
	}
	if logs == 0 {
		t.Error("nothing was logged about a refused rung")
	}
}

// TestLadderMaxAttempts bounds how many upstream connections one client
// connection may cost.
func TestLadderMaxAttempts(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		conns = append(conns, newScriptConn(step{err: resetErr()}))
	}
	l := &flow.LadderRunner{
		Dial:        &scriptDialer{conns: conns},
		RTT:         flow.NewRTTTracker(),
		MaxAttempts: 2,
		TotalBudget: 3 * time.Second,
	}
	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err == nil {
		t.Fatal("want an error")
	}
	if len(out.Attempts) != 2 {
		t.Fatalf("attempts = %d, want the configured cap of 2", len(out.Attempts))
	}
}

// TestLadderOverARealSocket is the production wiring: NetDialer hands back a
// *net.TCPConn and the ladder wraps it in the same emit.SockTransport both front
// ends use.
func TestLadderOverARealSocket(t *testing.T) {
	t.Parallel()
	addr := rawOrigin(t, []byte("SERVERHELLO"))
	ap := netip.MustParseAddrPort(addr)
	h, m := hello(t, "discord.com")

	l := &flow.LadderRunner{
		Dial: &flow.NetDialer{Timeout: 2 * time.Second},
		RTT:  flow.NewRTTTracker(),
	}
	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: ap, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if _, ok := out.Conn.(*net.TCPConn); !ok {
		t.Fatalf("upstream is a %T, want a *net.TCPConn", out.Conn)
	}
	if out.Spec != "" || string(out.Pre) != "SERVERHELLO" {
		t.Fatalf("spec %q pre %q, want plain and the greeting", out.Spec, out.Pre)
	}
}
