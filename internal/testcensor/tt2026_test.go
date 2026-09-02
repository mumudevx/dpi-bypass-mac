package testcensor

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// TestTT2026BlocksPlainHello is the baseline row of MEASUREMENTS.md §3: a plain
// ClientHello to a listed name is blocked 0/3 on all three targets.
func TestTT2026BlocksPlainHello(t *testing.T) {
	hello := clientHello(t, "discord.com")
	v := feed(TT2026(), hello)
	if v.Action != ActionReset {
		t.Fatalf("plain hello for a blocked name: got %v, want reset", v)
	}
	if v.Match != "discord.com" {
		t.Errorf("match = %q, want discord.com", v.Match)
	}
}

// TestTT2026PassesBenignSNI is the control that ran in every measured trial
// (§1: same IP, same port, cloudflare.com returns 301 while discord.com is
// reset). A model that blocks the control is modelling an IP block, not this
// DPI.
func TestTT2026PassesBenignSNI(t *testing.T) {
	hello := clientHello(t, "cloudflare.com")
	if v := feed(TT2026(), hello); v.Blocked() {
		t.Fatalf("benign SNI was blocked: %v", v)
	}
}

// TestTT2026LabelAnchoredBlocklist pins that the blocklist matches on label
// boundaries. "notdiscord.com" is not "discord.com", and a censor simulator that
// conflates them would silently validate a matcher bug downstream.
func TestTT2026LabelAnchoredBlocklist(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"discord.com", true},
		{"cdn.discordapp.com", true},
		{"a.b.discord.com", true},
		{"notdiscord.com", false},
		{"discord.com.evil.tld", false},
		{"media.discordapp.net", false}, // §1: reaches the origin, 401
		{"discord.media", false},        // §1: reaches the origin, 520
	} {
		hello := clientHello(t, tc.name)
		got := feed(TT2026(), hello).Blocked()
		if got != tc.want {
			t.Errorf("%s: blocked = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestTT2026FirstRecordRule is the centrepiece: MEASUREMENTS.md §3.2's 66
// shuffled trials, restated as a predicate over the cut offset.
//
// The measured table (body=1497, sni at [112,122), both records in ONE TCP
// segment) is:
//
//	sniStart-20, sniStart-1, sniStart, sniStart+1, sniMid, sniEnd-1   3/3 through
//	sniEnd, sniEnd+1, sniEnd+20, sniEnd+200                           0/3 blocked
//
// The boundary is exactly sniEnd. Offsets here are computed from the captured
// hello's own SNI extent rather than hard-coded at 112/122, because the rule is
// relative and the hello is whatever Go emits today.
func TestTT2026FirstRecordRule(t *testing.T) {
	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	m := tlsmsg.Parse(hello, 443)

	cases := []struct {
		name    string
		cut     int
		blocked bool
	}{
		{"sniStart-20", sniStart - 20, false},
		{"sniStart-1", sniStart - 1, false},
		{"sniStart", sniStart, false},
		{"sniStart+1", sniStart + 1, false},
		{"sniMid", (sniStart + sniEnd) / 2, false},
		{"sniEnd-1", sniEnd - 1, false},
		{"sniEnd", sniEnd, true},
		{"sniEnd+1", sniEnd + 1, true},
		{"sniEnd+20", sniEnd + 20, true},
		{"sniEnd+200", sniEnd + 200, true},
	}
	for _, tc := range cases {
		if tc.cut <= 0 || tc.cut >= m.BodyLen {
			t.Fatalf("%s: cut %d is outside the body (len %d); the capture changed shape",
				tc.name, tc.cut, m.BodyLen)
		}
		// One TCP segment, two records — the exact wire shape §3.2 measured.
		got := feed(TT2026(), split(t, hello, tc.cut)).Blocked()
		if got != tc.blocked {
			t.Errorf("cut at %s (%d, sni=[%d,%d)): blocked = %v, want %v",
				tc.name, tc.cut, sniStart, sniEnd, got, tc.blocked)
		}
	}

	// The predicate the implementation encodes must agree with the table above.
	limit, ok := m.MaxFirstRecordEnd()
	if !ok || limit != sniEnd-1 {
		t.Fatalf("MaxFirstRecordEnd = (%d, %v), want (%d, true)", limit, ok, sniEnd-1)
	}
}

// TestTT2026ReassemblesTCP is MEASUREMENTS.md §3.1: every two-segment TCP split
// failed, including split2-in-sni which cuts inside the hostname. TCP framing is
// not the mechanism, and a model that let a TCP split through would green-light
// an emitter measured at 0/5.
func TestTT2026ReassemblesTCP(t *testing.T) {
	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	mid := 5 + (sniStart+sniEnd)/2 // absolute: inside the hostname

	for _, tc := range []struct {
		name string
		at   int
	}{
		{"split2-at-1", 1},
		{"split2-at-3", 3},
		{"split2-at-64", 64},
		{"split2-in-sni", mid},
	} {
		if v := feed(TT2026(), hello[:tc.at], hello[tc.at:]); !v.Blocked() {
			t.Errorf("%s: passed, but §3.1 measured every TCP split at 0/5", tc.name)
		}
	}

	// chunk-N is the same story at a different granularity: reassembly makes the
	// segment size irrelevant to this model. §3.4's measured chunk passes are
	// non-monotonic and deliberately not modelled; see TT2026's doc comment.
	for _, size := range []int{4, 12, 40} {
		var segs [][]byte
		for i := 0; i < len(hello); i += size {
			segs = append(segs, hello[i:min(i+size, len(hello))])
		}
		if v := feed(TT2026(), segs...); !v.Blocked() {
			t.Errorf("chunk-%d passed; TT2026 reassembles TCP by construction", size)
		}
	}
}

// TestTT2026TwoRecordsOneSegment is the measurement that isolates the mechanism:
// tlsrec2-1seg passed 3/3 on all three targets, so the bypass is at the record
// layer and needs no timing, no socket options and no root (§3.1, §3.3).
func TestTT2026TwoRecordsOneSegment(t *testing.T) {
	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	one := split(t, hello, (sniStart+sniEnd)/2)

	if v := feed(TT2026(), one); v.Blocked() {
		t.Fatalf("two records in one segment were blocked: %v", v)
	}
	// The same two records spread over many TCP segments must also pass: the
	// record boundary is what matters, not the segment boundary.
	var segs [][]byte
	for i := 0; i < len(one); i += 7 {
		segs = append(segs, one[i:min(i+7, len(one))])
	}
	if v := feed(TT2026(), segs...); v.Blocked() {
		t.Fatalf("two records across many segments were blocked: %v", v)
	}
}

// TestTT2026PeriodicRecords covers the tlsevery rows of §3: every-16 and
// every-64 pass, every-256 is blocked. One predicate — does record 1 end at or
// before sniEnd-1 — explains all three, which is the claim §3.3 rests on.
func TestTT2026PeriodicRecords(t *testing.T) {
	hello := clientHello(t, "discord.com")
	_, sniEnd := sniExtent(t, hello)
	m := tlsmsg.Parse(hello, 443)

	for _, period := range []int{16, 64, 256} {
		var cuts []int
		for c := period; c < m.BodyLen; c += period {
			cuts = append(cuts, c)
		}
		out, err := tlsmsg.SplitRecord(hello, cuts)
		if err != nil {
			t.Fatalf("period %d: %v", period, err)
		}
		want := period > sniEnd-1
		if got := feed(TT2026(), out).Blocked(); got != want {
			t.Errorf("tlsrec-every-%d: blocked = %v, want %v (sniEnd-1 = %d)",
				period, got, want, sniEnd-1)
		}
	}
}

// TestTT2026OOBEvades covers the oob rows of §3: an urgent byte at offset 1 or 3
// passed 3/3. The mechanism modelled is that the middlebox counts the urgent
// byte as stream data while the receiving TCP does not deliver it, so the two
// disagree about where the ClientHello starts.
func TestTT2026OOBEvades(t *testing.T) {
	hello := clientHello(t, "discord.com")
	for _, at := range []int{1, 3} {
		in := TT2026().Inspect(443)
		if _, deliver := in.Client(hello[:at], 0); !deliver {
			t.Fatalf("head segment was not delivered")
		}
		if v := in.ClientOOB([]byte{0xff}); v.Blocked() {
			t.Fatalf("oob-at-%d: blocked before the tail arrived: %v", at, v)
		}
		v, _ := in.Client(hello[at:], 0)
		if v.Blocked() {
			t.Errorf("oob-at-%d: blocked, but §3 measured 3/3 through", at)
		}
	}
}

// TestNaiveModelContrast pins that a plain TCP split defeats a substring matcher
// but not TT2026. The distinction is the whole reason MEASUREMENTS.md §3.1
// exists, and a test suite written only against Naive would have shipped
// split2-in-sni, which measures 0/5 in Turkey.
func TestNaiveModelContrast(t *testing.T) {
	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	at := 5 + (sniStart+sniEnd)/2

	naive := Naive()
	naive.ReassembleTCP = false
	if v := feed(naive, hello[:at], hello[at:]); v.Blocked() {
		t.Fatalf("a hostname-splitting TCP split should evade a non-reassembling matcher: %v", v)
	}
	if v := feed(TT2026(), hello[:at], hello[at:]); !v.Blocked() {
		t.Fatalf("the same split must NOT evade TT2026: %v", v)
	}
	if v := feed(Naive(), hello); !v.Blocked() {
		t.Fatalf("a plain hello must be blocked even by the naive model: %v", v)
	}
}

// TestModelInspectBytes covers the give-up window: a middlebox that only reads
// the first N bytes of a flow forwards everything after it.
func TestModelInspectBytes(t *testing.T) {
	hello := clientHello(t, "discord.com")
	m := TT2026()
	m.InspectBytes = 32
	if v := feed(m, hello); v.Blocked() {
		t.Fatalf("a 32-byte inspection window cannot see the SNI: %v", v)
	}
	m.InspectBytes = len(hello)
	if v := feed(m, hello); !v.Blocked() {
		t.Fatalf("a full-length window must still block: %v", v)
	}
}

// TestModelMinTTL covers the fake-segment mechanism: a segment written below the
// hop count to the origin is seen by the middlebox and never delivered.
func TestModelMinTTL(t *testing.T) {
	m := TT2026()
	m.MinTTL = 6
	in := m.Inspect(443)
	if _, deliver := in.Client([]byte("junk"), 1); deliver {
		t.Errorf("a TTL-1 segment must not reach the origin")
	}
	if _, deliver := in.Client([]byte("junk"), 64); !deliver {
		t.Errorf("a full-TTL segment must reach the origin")
	}
	if _, deliver := in.Client([]byte("junk"), 0); !deliver {
		t.Errorf("the socket default (0) must reach the origin")
	}
}

// TestModelPortScope pins that a model with an explicit port list ignores every
// other port. Without it a DNS or plaintext-HTTP test would be silently
// interfered with by a TLS model.
func TestModelPortScope(t *testing.T) {
	hello := clientHello(t, "discord.com")
	in := TT2026().Inspect(80)
	v, deliver := in.Client(hello, 0)
	if v.Blocked() || !deliver {
		t.Fatalf("port 80 is outside the model's scope: %v deliver=%v", v, deliver)
	}
	if !strings.Contains(in.Verdict().Reason, "not inspected") {
		t.Errorf("reason = %q, want it to name the port scope", in.Verdict().Reason)
	}
}

// TestIPBlockFiresBeforeAnyBytes is the ShapeIPBlock signature: the flow dies
// with no payload written at all, so even a benign SNI to the same address
// fails. §1 measured the opposite on Türk Telekom, which is precisely why a
// prober must be able to tell the two apart.
func TestIPBlockFiresBeforeAnyBytes(t *testing.T) {
	m := IPBlock(netip.MustParsePrefix("162.159.128.0/24"))
	in := m.Inspect(443)
	v := in.Dst(netip.MustParseAddr("162.159.128.233"))
	if v.Action != ActionReset {
		t.Fatalf("address block: got %v, want reset", v)
	}
	if in2 := m.Inspect(443); in2.Dst(netip.MustParseAddr("1.1.1.1")).Blocked() {
		t.Fatalf("an address outside the blocked prefix must pass")
	}
}

func TestActionAndVerdictStrings(t *testing.T) {
	if got := ActionAlert.String(); got != "alert" {
		t.Errorf("ActionAlert = %q", got)
	}
	if got := Action(99).String(); got != "invalid" {
		t.Errorf("Action(99) = %q", got)
	}
	v := Verdict{Action: ActionReset, Reason: "why", Match: "discord.com"}
	if !strings.Contains(v.String(), "discord.com") || !strings.Contains(v.String(), "reset") {
		t.Errorf("Verdict.String() = %q", v.String())
	}
	if got := (Verdict{Reason: "clean"}).String(); !strings.Contains(got, "pass") {
		t.Errorf("pass verdict = %q", got)
	}
	if got := RoleAltPort.String(); got != "altport" {
		t.Errorf("RoleAltPort = %q", got)
	}
	if got := DNSRole(9).String(); got != "invalid" {
		t.Errorf("DNSRole(9) = %q", got)
	}
}

// chunkSegments reproduces the shipped chunk emitter's write geometry: at most
// budgetBoundaries cuts of `size` bytes over the head of the message, with
// everything left over in one final write.
//
// MEASUREMENTS.md §3.4's correction note is about exactly this shape — "a chunk
// size is meaningless without the write geometry it was measured under" — so a
// test that chunked the whole message would be measuring a different emitter
// from the one the ladder ships.
func chunkSegments(msg []byte, size, budgetBoundaries int) [][]byte {
	var segs [][]byte
	prev := 0
	for o := size; o < len(msg) && len(segs) < budgetBoundaries; o += size {
		segs = append(segs, msg[prev:o])
		prev = o
	}
	return append(segs, msg[prev:])
}

// hostnameContiguous reports whether any single segment carries the whole
// hostname. It is the predicate NoReassembly enforces, computed independently
// of the model so the test asserts an agreement rather than a tautology.
func hostnameContiguous(segs [][]byte, name string) bool {
	for _, s := range segs {
		if strings.Contains(strings.ToLower(string(s)), strings.ToLower(name)) {
			return true
		}
	}
	return false
}

// TestChunkEvadesANonReassemblingMiddlebox is the bypass-level assertion the
// chunk rungs never had.
//
// Every model in this package reassembles TCP, so chunking was scored only as a
// failure and the rungs were pinned by shape assertions alone: a regression
// that kept the segment count and sizes while writing the hostname contiguously
// into one segment passed the entire suite. The assertion here is the PREDICATE
// rather than a list of sizes — which sizes ship is the ladder's business, and
// MEASUREMENTS.md §3.5 is explicit that a size is not portable between
// implementations — so it holds whatever rungs the ladder ends up carrying.
func TestChunkEvadesANonReassemblingMiddlebox(t *testing.T) {
	hello := clientHello(t, "discord.com")
	const host = "discord.com"

	// The shipped budget: 16 segments, so 15 boundaries and one tail write.
	// MEASUREMENTS.md §3.4's correction table was measured at this geometry.
	const boundaries = 15

	var evaded, blocked []int
	for size := 1; size <= 64; size++ {
		segs := chunkSegments(hello, size, boundaries)
		want := hostnameContiguous(segs, host)
		got := feed(NoReassembly(), segs...).Blocked()
		if got != want {
			t.Errorf("chunk-%d over %d segments: blocked = %v, want %v (hostname contiguous in one segment = %v)",
				size, len(segs), got, want, want)
		}
		if got {
			blocked = append(blocked, size)
		} else {
			evaded = append(evaded, size)
		}
	}

	// The contrast must actually contrast: a model nothing evades and a model
	// everything evades are both worthless as assertions.
	if len(evaded) == 0 {
		t.Fatal("no chunk size evaded the contrast model; the rungs still have no bypass-level assertion")
	}
	if len(blocked) == 0 {
		t.Fatal("every chunk size evaded the contrast model; it asserts nothing about the emitter")
	}
	t.Logf("chunk sizes 1..64 over %d boundaries: %d evade, %d are blocked", boundaries, len(evaded), len(blocked))

	// And the honest negative stays true: none of this evades the measured
	// model, because §3.1 measured Türk Telekom as reassembling TCP.
	for _, size := range []int{evaded[0], evaded[len(evaded)-1]} {
		segs := chunkSegments(hello, size, boundaries)
		if !feed(TT2026(), segs...).Blocked() {
			t.Errorf("chunk-%d evaded TT2026; §3.1 says TCP framing is not the mechanism there", size)
		}
	}
}

// TestNoReassemblyIsNotVacuous pins the two ends of the contrast model, so a
// change that quietly turned it into "everything passes" is a failure rather
// than a silently weaker suite.
func TestNoReassemblyIsNotVacuous(t *testing.T) {
	hello := clientHello(t, "discord.com")

	// One write carrying the whole hello: nothing to evade with.
	if v := feed(NoReassembly(), hello); !v.Blocked() {
		t.Fatalf("a plain hello in one segment must be blocked: %v", v)
	}
	// A benign name is not blocked, so the model is matching hostnames rather
	// than shapes.
	if v := feed(NoReassembly(), clientHello(t, "cloudflare.com")); v.Blocked() {
		t.Fatalf("benign SNI was blocked: %v", v)
	}
	// The two models are genuinely independent, and a cut before the hostname
	// shows it. tlsfrag:pos=snistart-20 ends record 1 before the SNI, so TT2026
	// never matches (§3.2) — but it emits ONE TCP segment carrying two records
	// (§3.1 measured that shape at 3/3 on the real line) with the hostname
	// still contiguous in it, so a segment-wise scanner does match. Neither
	// rung is a bypass against both mechanisms, which is why the ladder needs
	// more than one rung and why the suite needs more than one model.
	sniStart, _ := sniExtent(t, hello)
	early := split(t, hello, sniStart-20)
	if v := feed(TT2026(), early); v.Blocked() {
		t.Fatalf("a cut before the SNI must evade TT2026 (§3.2): %v", v)
	}
	if v := feed(NoReassembly(), early); !v.Blocked() {
		t.Fatalf("the same cut leaves the hostname whole in one segment, so a "+
			"segment-wise scanner must still match: %v", v)
	}
}
