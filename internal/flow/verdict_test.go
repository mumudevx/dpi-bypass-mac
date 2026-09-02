package flow_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// fatalAlert is what MEASUREMENTS.md §5 records www.yapikredi.com.tr answering
// a ClientHello that spans two records with: alert(21), TLS 1.2 record version,
// 2-byte body, level fatal(2), illegal_parameter(47). Seven bytes.
var fatalAlert = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f}

// serverHello is a plausible first response from a real terminator: a handshake
// record, which is the only shape that is evidence a rung worked.
var serverHello = []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}

// sinkhole is the BTK block-page address MEASUREMENTS.md §2 measures the system
// resolver returning for every blocked name, and §5.4 records completing a TLS
// handshake with a 1404-byte self-signed ServerHello.
var sinkhole = netip.MustParseAddrPort("195.175.254.2:443")

// TestLadderTLSAlertIsNotAWin is the first of the two defects the architecture
// rests on. A fragile terminator that REJECTS a desynced hello answers with a
// fatal alert, and those seven bytes used to be scored a win: the bank was then
// pinned to the emitter that breaks it for a week, with the TTL refreshed on
// every connection, so demotion was structurally unreachable.
//
// Committing on the bytes is still right — the client is about to see them —
// but committing and "this rung worked" are two different questions.
func TestLadderTLSAlertIsNotAWin(t *testing.T) {
	t.Parallel()
	const name = "www.yapikredi.com.tr"
	h, m := hello(t, name)
	store := newMemStore()
	// Five sequential connections, each one a plain attempt the DPI resets and
	// a tlsfrag attempt the bank answers with the alert. Nothing may
	// accumulate: the review's repro of the defect showed wins climbing 1..5
	// with the 168h expiry refreshed every time and losses stuck at 0.
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		conns = append(conns,
			newScriptConn(step{err: resetErr()}),  // plain: censorship-shaped
			newScriptConn(step{data: fatalAlert})) // tlsfrag: the bank rejects it
	}
	sd := &scriptDialer{conns: conns}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}

	for i := 0; i < 5; i++ {
		out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443},
			watchVerdict(), h, m, nil)
		if err != nil {
			t.Fatalf("run %d: %v (attempts %v)", i, err, specsOf(out.Attempts))
		}
		// The connection is committed and must be handed over: the alert is
		// the origin's to deliver, and a retry would duplicate bytes.
		if out.Conn == nil || string(out.Pre) != string(fatalAlert) {
			t.Fatalf("run %d: conn %v pre %x, want the alert handed to the client",
				i, out.Conn != nil, out.Pre)
		}
		out.Conn.Close()
		last := out.Attempts[len(out.Attempts)-1]
		if !last.Rejected {
			t.Errorf("run %d: attempt %q was not marked rejected", i, last.Spec)
		}
		if v, ok := store.Get(policy.NetworkID{}, name); ok {
			t.Fatalf("run %d cached %s/%q wins=%d: a TLS alert pinned the bank to the spec that "+
				"breaks it for %v, and the TTL refreshes on every connection",
				i, v.Class, v.Spec, v.Wins, time.Until(v.Expires))
		}
	}
}

// TestLadderAlertDropsACachedDesync: once a cached spec starts producing
// alerts it is dropped on the FIRST one, not counted towards three losses.
// The evidence is the terminator's own and re-sending the spec twice more only
// breaks the same handshake twice more.
func TestLadderAlertDropsACachedDesync(t *testing.T) {
	t.Parallel()
	const name = "www.yapikredi.com.tr"
	h, m := hello(t, name)
	store := newMemStore()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	cached := policy.Verdict{
		Class:   policy.ScopeDesync,
		Spec:    "tlsfrag:pos=snimid",
		Source:  policy.SrcLearnedDesync,
		Wins:    3,
		Learned: now.Add(-time.Hour),
		Expires: now.Add(flow.LearnedDesyncTTL),
		Ladder:  watchVerdict().Ladder,
	}
	if err := store.Put(policy.NetworkID{}, name, cached); err != nil {
		t.Fatalf("seed the store: %v", err)
	}

	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{data: fatalAlert})}}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker(),
		Now: func() time.Time { return now }}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443},
		cached, h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()

	v := store.get(t, name)
	if v.Source == policy.SrcLearnedDesync || v.Spec != "" {
		t.Fatalf("cached verdict is still %s/%q wins=%d expires=%v; an alert must drop it on the first one",
			v.Source, v.Spec, v.Wins, v.Expires)
	}
}

// TestLadderBytesThenResetIsNotAWin: a forged response followed by a reset is a
// middlebox signature, and judge returns both the bytes and the error. The
// bytes commit the connection; they are not evidence.
func TestLadderBytesThenResetIsNotAWin(t *testing.T) {
	t.Parallel()
	const name = "discord.com"
	h, m := hello(t, name)
	store := newMemStore()
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{data: []byte("HTTP/1.1 403"), err: resetErr()}),
	}}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if string(out.Pre) != "HTTP/1.1 403" {
		t.Fatalf("Pre = %q, want the bytes that committed the connection", out.Pre)
	}
	if v, ok := store.Get(policy.NetworkID{}, name); ok {
		t.Fatalf("cached %s/%s from one byte and a reset", v.Class, v.Source)
	}
}

// TestLadderNeverLearnsFromASinkhole is the second half of the plain-verdict
// defect. MEASUREMENTS.md §5.4: the BTK sinkhole COMPLETES the handshake and
// returns a self-signed ServerHello, so "the upstream answered" is true and
// means nothing. internal/probe already scores a connected sinkhole as
// VerdictBlockPage; the ladder has to agree or it caches "plain works here"
// for a name that is blocked.
func TestLadderNeverLearnsFromASinkhole(t *testing.T) {
	t.Parallel()
	const name = "discord.com"
	h, m := hello(t, name)
	store := newMemStore()
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConnFrom(sinkhole, step{data: serverHello}),
	}}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: sinkhole, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if v, ok := store.Get(policy.NetworkID{}, name); ok {
		t.Fatalf("cached %s/%s expires-zero=%v from the block page", v.Class, v.Source, v.Expires.IsZero())
	}
}

// TestLadderSinkholesAreConfigurable: a front end wires its resolver's own
// sinkhole list in, so a network whose censor answers from a different address
// is covered without a rebuild. The list may also carry an invalid entry from
// a config file, which must be ignored rather than matching everything.
func TestLadderSinkholesAreConfigurable(t *testing.T) {
	t.Parallel()
	const name = "discord.com"
	h, m := hello(t, name)
	store := newMemStore()
	// Three bytes of an alert record: enough to recognise, not enough to name
	// the level and description.
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{data: []byte{0x15, 0x03, 0x03}})}}
	l := &flow.LadderRunner{
		Dial: sd, Store: store, RTT: flow.NewRTTTracker(),
		Sinkholes: []netip.Addr{{}, netip.MustParseAddr("203.0.113.9")},
	}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()
	if v, ok := store.Get(policy.NetworkID{}, name); ok {
		t.Fatalf("cached %s/%s from a truncated alert record", v.Class, v.Source)
	}
	if !out.Attempts[0].Rejected {
		t.Error("a three-byte alert record was not recognised as a rejection")
	}
}

// TestFlowSinkholesMatchResolve pins flow's copy of the sinkhole table to
// resolve's. flow cannot import resolve (resolve imports flow), but the test
// binary can, so the copy is mechanical rather than a promise in a comment.
func TestFlowSinkholesMatchResolve(t *testing.T) {
	t.Parallel()
	if len(flow.DefaultSinkholes) != len(resolve.DefaultSinkholes) {
		t.Fatalf("flow has %d sinkholes, resolve has %d: %v vs %v",
			len(flow.DefaultSinkholes), len(resolve.DefaultSinkholes),
			flow.DefaultSinkholes, resolve.DefaultSinkholes)
	}
	for i, a := range resolve.DefaultSinkholes {
		if flow.DefaultSinkholes[i] != a {
			t.Errorf("sinkhole %d = %v, resolve has %v", i, flow.DefaultSinkholes[i], a)
		}
	}
}

// TestLadderPlainWinExpires: a learned-plain verdict carries a TTL. It cannot
// revalidate itself — policy rewrites SrcLearnedPlain to ScopeDirect, which is
// relayed with no buffering, so the ladder is never invoked for that host
// again — and MEASUREMENTS.md §4 records months-scale rot in both directions.
func TestLadderPlainWinExpires(t *testing.T) {
	t.Parallel()
	const name = "www.akbank.com"
	h, m := hello(t, name)
	store := newMemStore()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{data: serverHello})}}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker(),
		Now: func() time.Time { return now }}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()

	v := store.get(t, name)
	if v.Source != policy.SrcLearnedPlain {
		t.Fatalf("cached source = %s, want SrcLearnedPlain", v.Source)
	}
	if want := now.Add(flow.LearnedPlainTTL); !v.Expires.Equal(want) {
		t.Fatalf("Expires = %v, want %v: a plain verdict that never expires can never be re-tested",
			v.Expires, want)
	}
}

// TestLadderTruncatedHelloSilenceHandsOverPlain is the destructive-tail defect.
// With a truncated first message every rung carrying ReqComplete is refused
// before the dial, so the tr ladder collapses to [plain, oob:pos=1] — and
// because oob was the last index the silence handover fired and the connection
// carrying an MSG_OOB junk byte was handed to the client as the winner, at a
// bank, where oob measured 0/20 (MEASUREMENTS.md §5.1).
//
// The plain rung is now the last rung that can be emitted, so silence on it
// hands over the PLAIN connection and no junk byte is ever written.
func TestLadderTruncatedHelloSilenceHandsOverPlain(t *testing.T) {
	t.Parallel()
	const name = "www.akbank.com"
	h, _ := hello(t, name)
	part := h[:len(h)-40]
	m := tlsmsg.Parse(part, 443)
	m.Truncated = true
	if m.Complete {
		t.Fatal("fixture is not truncated")
	}

	silent := newScriptConn() // never answers
	sd := &scriptDialer{conns: []net.Conn{silent, newScriptConn(step{data: serverHello})}}
	store := newMemStore()
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker(),
		TotalBudget: 4 * time.Second}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443},
		watchVerdict(), part, m, nil)
	if err != nil {
		t.Fatalf("Run: %v (attempts %v)", err, specsOf(out.Attempts))
	}
	defer out.Conn.Close()

	if out.Spec != "" {
		t.Fatalf("winning spec = %q, want plain: a hello we truncated ourselves is not evidence "+
			"and must never reach the destructive tail", out.Spec)
	}
	if sd.count() != 1 {
		t.Fatalf("dialled %d times, want 1", sd.count())
	}
	if n := len(silent.oob); n != 0 {
		t.Fatalf("%d urgent byte(s) were written on a truncated hello", n)
	}
	if v, ok := store.Get(policy.NetworkID{}, name); ok {
		t.Fatalf("a handover cached %s/%s; silence is not a result", v.Class, v.Source)
	}
}

// TestLadderNeverHandsOverAPoisonedSocket: the handover exists so a merely slow
// origin is not torn down. That trade is free for plain and for a pure
// reframing — the origin sees the same bytes either way — and it is not free
// for oob, which leaves a junk byte in the stream. No connection beats a
// poisoned one.
func TestLadderNeverHandsOverAPoisonedSocket(t *testing.T) {
	t.Parallel()
	const name = "www.isbank.com.tr"
	h, m := hello(t, name)
	silent := newScriptConn()
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{err: resetErr()}), silent}}
	l := &flow.LadderRunner{Dial: sd, RTT: flow.NewRTTTracker(), TotalBudget: 4 * time.Second}
	v := policy.Verdict{Class: policy.ScopeWatch, Ladder: []string{"", "oob:pos=1"}}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443}, v, h, m, nil)
	if err == nil {
		defer out.Conn.Close()
		t.Fatalf("an oob-poisoned socket was handed to the client as spec %q", out.Spec)
	}
	if out.Conn != nil {
		t.Fatal("a failed walk must not hand back a connection")
	}
}

// TestLadderHandsOverASilentReframingRung is the other direction of the same
// gate, and it must not be tightened away: a reframing rung puts exactly the
// client's own bytes on the wire, so a slow origin behind one is still worth
// handing over rather than tearing down. Only the rungs that leave an artefact
// (an urgent byte, a lowered hop limit) are refused.
func TestLadderHandsOverASilentReframingRung(t *testing.T) {
	t.Parallel()
	const name = "slow.example"
	h, m := hello(t, name)
	store := newMemStore()
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}), // plain
		newScriptConn(),                      // chunk: silence, and nothing left to try
	}}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker(),
		TotalBudget: 4 * time.Second}
	v := policy.Verdict{Class: policy.ScopeWatch, Ladder: []string{"", "chunk:size=12"}}

	out, err := l.Run(context.Background(), flow.Target{Name: name, Addr: testAddr, Port: 443}, v, h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v: a merely slow origin behind a reframing rung must not be torn down", err)
	}
	defer out.Conn.Close()
	if out.Spec != "chunk:size=12" {
		t.Fatalf("spec = %q, want the silent chunk rung handed over", out.Spec)
	}
	if v, ok := store.Get(policy.NetworkID{}, name); ok {
		t.Fatalf("silence cached %s/%s; a handover learns nothing", v.Class, v.Source)
	}
}

// TestLadderObservesTheDialledAddress: the RTT tracker keys on the address the
// dial actually used. Target.Addr is the PINNED address and every proxy-mode
// flow carries a name and no address, so keying on it made the tracker dead
// code: it never learned anything, Known() was always false, and every attempt
// used the flat 2 s window — which blows the 5 s walk budget in three rungs.
func TestLadderObservesTheDialledAddress(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	rtt := flow.NewRTTTracker()
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{data: serverHello})}}
	l := &flow.LadderRunner{Dial: sd, RTT: rtt}

	// A name and a port, and no pinned address: what the proxy datapath builds.
	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()

	if rtt.Len() != 1 || !rtt.Known(testAddr.Addr()) {
		t.Fatalf("tracker holds %d destination(s) and does not know %v; the adaptive window never engages",
			rtt.Len(), testAddr.Addr())
	}
	if got := out.Attempts[0].Addr; got != testAddr.Addr() {
		t.Errorf("Attempt.Addr = %v, want the address the dial used (%v)", got, testAddr.Addr())
	}
}

// slowDialer takes a fixed time to connect, which is the shape that starves a
// singleflight follower: the follower pays the same dial the leader just paid.
type slowDialer struct {
	delay time.Duration

	mu    sync.Mutex
	conns []net.Conn
	dials int
}

func (d *slowDialer) DialTCP(ctx context.Context, _ flow.Target) (net.Conn, error) {
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	i := d.dials
	d.dials++
	if i >= len(d.conns) {
		return nil, net.ErrClosed
	}
	return d.conns[i], nil
}

// TestSingleflightFollowerGetsItsOwnBudget: the walk budget bounds ONE walk,
// and a follower's clock may not run through the leader's. It does not
// reproduce with a slow ORIGIN — a follower's re-walk is fast once the verdict
// is known — but it does with a slow DIAL, which the follower pays again.
// Singleflight was then strictly worse than not collapsing at all.
func TestSingleflightFollowerGetsItsOwnBudget(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	const (
		n     = 4
		dial  = 400 * time.Millisecond
		total = 600 * time.Millisecond
	)
	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		conns = append(conns, newScriptConn(step{data: serverHello}))
	}
	l := &flow.LadderRunner{
		Dial:        &slowDialer{delay: dial, conns: conns},
		Store:       newMemStore(),
		RTT:         flow.NewRTTTracker(),
		Single:      policy.NewSingleflight(),
		TotalBudget: total,
	}
	tgt := flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}

	var wg sync.WaitGroup
	errs := make([]error, n)
	outs := make([]flow.Outcome, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			outs[i], errs[i] = l.Run(context.Background(), tgt, watchVerdict(), h, m, nil)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("connection %d: %v; a follower must not spend the leader's budget", i, err)
			continue
		}
		_ = outs[i].Conn.Close()
	}
}

// TestLadderSkippedRungsDoNotCostAnAttempt: MaxAttempts bounds the upstream
// connections one client connection may cost, so a rung refused before the dial
// must not consume one. It also must not read as an escalation: M12's drift
// detector counts Outcome.Escalations().
func TestLadderSkippedRungsDoNotCostAnAttempt(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	sd := &scriptDialer{conns: []net.Conn{
		newScriptConn(step{err: resetErr()}),   // plain
		newScriptConn(step{data: serverHello}), // chunk:size=12, after oob is skipped
	}}
	l := &flow.LadderRunner{
		Dial:        sd,
		RTT:         flow.NewRTTTracker(),
		Caps:        strategy.CapStreamWrite | strategy.CapNoDelay, // no CapOOB
		MaxAttempts: 2,
	}
	v := policy.Verdict{Class: policy.ScopeWatch, Ladder: []string{"", "oob:pos=1", "chunk:size=12"}}

	out, err := l.Run(context.Background(), flow.Target{Name: "discord.com", Addr: testAddr, Port: 443},
		v, h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v (attempts %v); the skipped oob rung consumed the budget", err, specsOf(out.Attempts))
	}
	defer out.Conn.Close()
	if out.Spec != "chunk:size=12" {
		t.Fatalf("winning spec = %q, want chunk:size=12", out.Spec)
	}
	if len(out.Attempts) != 3 {
		t.Fatalf("attempts = %q, want all three rungs recorded for `dpb why`", specsOf(out.Attempts))
	}
	if out.Attempts[1].Emitted {
		t.Error("the oob rung was refused before the dial but is marked emitted")
	}
	if out.Escalations() != 1 {
		t.Fatalf("escalations = %d, want 1: only rungs that dialled escalated", out.Escalations())
	}
}

// TestLadderCachesAnUnnamedTarget: policy.Engine.forAddr reads the store with
// the address literal as the key for a TUN flow the ReverseMap could not name.
// Nothing ever wrote that key, so every unnamed flow re-walked the whole ladder
// on every connection.
func TestLadderCachesAnUnnamedTarget(t *testing.T) {
	t.Parallel()
	h, m := hello(t, "discord.com")
	store := newMemStore()
	sd := &scriptDialer{conns: []net.Conn{newScriptConn(step{data: serverHello})}}
	l := &flow.LadderRunner{Dial: sd, Store: store, RTT: flow.NewRTTTracker()}

	out, err := l.Run(context.Background(), flow.Target{Addr: testAddr, Port: 443},
		watchVerdict(), h, m, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer out.Conn.Close()

	v, ok := store.Get(policy.NetworkID{}, testAddr.Addr().String())
	if !ok {
		t.Fatalf("nothing cached under %q, which is the key the policy engine reads back",
			testAddr.Addr().String())
	}
	if v.Source != policy.SrcLearnedPlain {
		t.Fatalf("cached source = %s, want SrcLearnedPlain", v.Source)
	}
}
