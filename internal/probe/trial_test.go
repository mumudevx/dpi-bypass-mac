package probe_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// TestTT2026AcceptanceMatrix is the offline form of the milestone's acceptance
// criterion, run against the measured model instead of the measured line.
//
// The three rows are MEASUREMENTS.md §1 and §3.2 exactly: same destination,
// only the SNI and the emitter differ. A blocked name plain is reset; the same
// name with the record cut inside the hostname passes; a benign name to the
// same destination passes with no strategy at all, which is what proves a
// failure above it is the SNI and not the path.
func TestTT2026AcceptanceMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
		spec string
		want probe.Verdict
	}{
		{"blocked name, no desync", "discord.com", "", probe.VerdictReset},
		{"blocked name, record cut inside the SNI", "discord.com", "tlsfrag:pos=snimid", probe.VerdictPass},
		{"benign name, same destination", "cloudflare.com", "", probe.VerdictPass},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := newLab(t, testcensor.TT2026("discord.com"))
			opts := l.options(t)
			s := mustSpec(t, tc.spec)

			const reps = 5
			pass := 0
			for i := 0; i < reps; i++ {
				tr := probe.RunTrial(context.Background(), s, probe.Target{Host: tc.host}, i+1, opts)
				if tr.Verdict != tc.want {
					t.Fatalf("rep %d: verdict = %s (%s), want %s", i+1, tr.Verdict, tr.Err, tc.want)
				}
				if tr.Verdict == probe.VerdictPass {
					pass++
				}
				if tr.Round != i+1 {
					t.Errorf("rep %d: Round = %d", i+1, tr.Round)
				}
				if tr.Spec != s.Spec {
					t.Errorf("Spec = %q, want %q", tr.Spec, s.Spec)
				}
			}
			if tc.want == probe.VerdictPass && pass != reps {
				t.Fatalf("%d/%d PASS, want %d/%d", pass, reps, reps, reps)
			}
		})
	}
}

// The primary emitter reframes the record layer and emits ONE write.
// MEASUREMENTS.md §3.1: tlsrec2-1seg — two TLS records in a single TCP segment —
// goes through on all three targets, so TCP framing is irrelevant and the
// emitter must not pay for extra writes it does not need.
func TestTLSFragEmitsOneWrite(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026("discord.com"))

	tr := probe.RunTrial(context.Background(), mustSpec(t, "tlsfrag:pos=snimid"),
		probe.Target{Host: "discord.com"}, 1, l.options(t))

	if tr.Verdict != probe.VerdictPass {
		t.Fatalf("verdict = %s (%s)", tr.Verdict, tr.Err)
	}
	if tr.Segments != 1 {
		t.Errorf("Segments = %d, want 1: tlsfrag reframes records, it does not split segments", tr.Segments)
	}
}

// A scheduling op really does reach the wire as several writes. Without this a
// plan could silently collapse to one write and every chunk measurement would
// be a measurement of plain.
func TestChunkEmitsManyWrites(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026())

	tr := probe.RunTrial(context.Background(), mustSpec(t, "chunk:size=12"),
		probe.Target{Host: "cloudflare.com"}, 1, l.options(t))

	if tr.Verdict != probe.VerdictPass {
		t.Fatalf("verdict = %s (%s)", tr.Verdict, tr.Err)
	}
	if tr.Segments < 10 {
		t.Errorf("Segments = %d, want a ClientHello's worth of 12-byte writes", tr.Segments)
	}
}

// Whatever the emitter did to the record layer, the origin must reassemble the
// bytes the client wrote. A bypass tool that corrupts a stream is worse than no
// tool.
func TestEmittedStreamReachesTheOriginIntact(t *testing.T) {
	t.Parallel()
	for _, spec := range []string{"", "tlsfrag:pos=snimid", "chunk:size=12", "tlsevery:period=64"} {
		name := spec
		if name == "" {
			name = "plain"
		}
		t.Run(name, func(t *testing.T) {
			l := newLab(t, testcensor.TT2026())
			tr := probe.RunTrial(context.Background(), mustSpec(t, spec),
				probe.Target{Host: "cloudflare.com"}, 1, l.options(t))
			if tr.Verdict != probe.VerdictPass {
				t.Fatalf("verdict = %s (%s)", tr.Verdict, tr.Err)
			}
			got := l.origin.Received(0)
			if len(got) == 0 {
				t.Fatal("the origin received nothing")
			}
			// A completed, verified handshake through a real TLS server is the
			// integrity check: crypto/tls would have failed on a single wrong
			// byte. The record count is what is asserted separately.
			if got[0] != 0x16 {
				t.Errorf("first byte at the origin = %#x, want a handshake record", got[0])
			}
		})
	}
}

// A TLS terminator that refuses a handshake spanning two records is a
// compatibility fact about the origin, not a bypass fact about the DPI.
// MEASUREMENTS.md §5: www.yapikredi.com.tr answers a record-split ClientHello
// with "remote error: tls: illegal parameter". Scoring that as a strategy
// failure would let a server condition contaminate the ranking.
func TestFragileTerminatorIsHandshakeFailNotReset(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.Fragile())
	opts := l.options(t)

	plain := probe.RunTrial(context.Background(), mustSpec(t, ""),
		probe.Target{Host: "discord.com"}, 1, opts)
	if plain.Verdict != probe.VerdictPass {
		t.Fatalf("plain against a fragile terminator: verdict = %s (%s), want PASS", plain.Verdict, plain.Err)
	}

	split := probe.RunTrial(context.Background(), mustSpec(t, "tlsfrag:pos=snimid"),
		probe.Target{Host: "discord.com"}, 2, opts)
	if split.Verdict != probe.VerdictHandshakeFail {
		t.Fatalf("record split against a fragile terminator: verdict = %s (%s), want HANDSHAKE-FAIL",
			split.Verdict, split.Err)
	}
	if split.Verdict.Scorable() {
		t.Error("a server-side handshake refusal must not be scorable")
	}
}

// A silent drop is a different failure class from a reset and the ladder is
// required to treat them differently, so the prober has to be able to tell them
// apart (MEASUREMENTS.md §2 measures the DNS-side block as a drop, §1 measures
// the TCP-side one as a reset).
func TestSilentDropIsTimeoutNotReset(t *testing.T) {
	t.Parallel()
	m := testcensor.TT2026("discord.com")
	m.Action = testcensor.ActionDrop
	l := newLab(t, m)

	opts := l.options(t)
	opts.Timeout = 300 * time.Millisecond

	tr := probe.RunTrial(context.Background(), mustSpec(t, ""),
		probe.Target{Host: "discord.com"}, 1, opts)

	if tr.Verdict != probe.VerdictTimeout {
		t.Fatalf("verdict = %s (%s), want TIMEOUT", tr.Verdict, tr.Err)
	}
	if !tr.Verdict.Scorable() {
		t.Error("a timeout is evidence about the strategy and must be scorable")
	}
}

// An EOF before any handshake byte is the shape six of the ten fragile hosts in
// MEASUREMENTS.md §5 produce. It is a torn-down connection, which is the same
// scorable class as a reset — a ladder that only recognises ECONNRESET hangs on
// these hosts until a deadline.
func TestCleanCloseIsReset(t *testing.T) {
	t.Parallel()
	m := testcensor.TT2026("discord.com")
	m.Action = testcensor.ActionEOF
	l := newLab(t, m)

	tr := probe.RunTrial(context.Background(), mustSpec(t, ""),
		probe.Target{Host: "discord.com"}, 1, l.options(t))

	if tr.Verdict != probe.VerdictReset {
		t.Fatalf("verdict = %s (%s), want RESET", tr.Verdict, tr.Err)
	}
}

// PASS means the certificate validates for the name. A handshake that completes
// against a certificate for someone else is what a transparent block page looks
// like, and calling it PASS is how a prober invents a winner that does not
// exist.
func TestCertificateForAnotherNameIsBlockPage(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026(), "someone-else.example")

	tr := probe.RunTrial(context.Background(), mustSpec(t, ""),
		probe.Target{Host: "cloudflare.com"}, 1, l.options(t))

	if tr.Verdict != probe.VerdictBlockPage {
		t.Fatalf("verdict = %s (%s), want BLOCKPAGE", tr.Verdict, tr.Err)
	}
}

// MEASUREMENTS.md §2: the ISP resolver answers every blocked name with
// 195.175.254.2. Reaching it is not a strategy result, and §5.4 records an
// entire compatibility matrix invalidated by scoring emitters against it.
func TestPinnedSinkholeIsBlockPageWithoutDialling(t *testing.T) {
	t.Parallel()
	dialed := false
	opts := probe.TrialOptions{
		Dial: errDialer{err: errors.New("must not dial")},
		Logf: func(string, ...any) { dialed = true },
	}

	tr := probe.RunTrial(context.Background(), strategy.Strategy{},
		probe.Target{Host: "discord.com", Addr: "195.175.254.2"}, 1, opts)

	if tr.Verdict != probe.VerdictBlockPage {
		t.Fatalf("verdict = %s (%s), want BLOCKPAGE", tr.Verdict, tr.Err)
	}
	if dialed {
		t.Error("the sinkhole check must fire before the dial")
	}
	if !strings.Contains(tr.Err, "195.175.254.2") {
		t.Errorf("Err = %q, want it to name the sinkhole", tr.Err)
	}
}

// The IPv6 sentinel is a range, not a host: a censor answering from a /64 can
// move within it for free (DOSSIER GT19, RIPE netname BTK).
func TestIPv6SinkholeMatchesTheContainingPrefix(t *testing.T) {
	t.Parallel()
	tr := probe.RunTrial(context.Background(), strategy.Strategy{},
		probe.Target{Host: "discord.com", Addr: "2a01:358:4014:a00::99"}, 1,
		probe.TrialOptions{Dial: errDialer{err: errors.New("must not dial")}})

	if tr.Verdict != probe.VerdictBlockPage {
		t.Fatalf("verdict = %s (%s), want BLOCKPAGE for an address inside the sinkhole /64", tr.Verdict, tr.Err)
	}
}

// A peer that turns out to be a sinkhole is caught after the dial too: with no
// --addr the answer comes from the chain, and the chain can be poisoned.
func TestConnectedSinkholeIsBlockPage(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026())
	opts := l.options(t)
	opts.Sinkholes = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

	tr := probe.RunTrial(context.Background(), mustSpec(t, ""),
		probe.Target{Host: "cloudflare.com"}, 1, opts)

	if tr.Verdict != probe.VerdictBlockPage {
		t.Fatalf("verdict = %s (%s), want BLOCKPAGE", tr.Verdict, tr.Err)
	}
	if !tr.Peer.IsValid() {
		t.Error("Peer must record the address actually reached")
	}
}

func TestDialFailure(t *testing.T) {
	t.Parallel()
	tr := probe.RunTrial(context.Background(), strategy.Strategy{},
		probe.Target{Host: "discord.com"}, 1,
		probe.TrialOptions{Dial: errDialer{err: errors.New("no route to host")}})

	if tr.Verdict != probe.VerdictDialFail {
		t.Fatalf("verdict = %s, want DIAL-FAIL", tr.Verdict)
	}
	if tr.Verdict.Scorable() {
		t.Error("a dial failure says nothing about the emitter and must not be scorable")
	}
	if !strings.Contains(tr.Err, "no route to host") {
		t.Errorf("Err = %q, want the dial error preserved", tr.Err)
	}
}

// A capability the transport does not have must be a LOCAL error, never a
// strategy failure: the strategy never reached the wire, so nothing about it
// was measured.
func TestMissingCapabilityIsLocalErrorNotAStrategyFailure(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026())
	l.caps = strategy.CapStreamWrite | strategy.CapNoDelay // no CapOOB
	opts := l.options(t)

	tr := probe.RunTrial(context.Background(), mustSpec(t, "oob:pos=1"),
		probe.Target{Host: "cloudflare.com"}, 1, opts)

	if tr.Verdict != probe.VerdictLocalError {
		t.Fatalf("verdict = %s (%s), want LOCAL-ERROR", tr.Verdict, tr.Err)
	}
	if tr.Verdict.Scorable() {
		t.Error("a local error must never be scored against a strategy")
	}
}

// Strict mode is what stops the prober scoring a strategy it did not emit: a
// hostname mutator has nothing to key on inside a TLS ClientHello, and a silent
// fallback to plain would be reported under the mutator's name.
func TestStrictModeRefusesASilentDowngrade(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026())

	tr := probe.RunTrial(context.Background(), mustSpec(t, "hostcase"),
		probe.Target{Host: "cloudflare.com"}, 1, l.options(t))

	if tr.Verdict != probe.VerdictLocalError {
		t.Fatalf("verdict = %s (%s), want LOCAL-ERROR", tr.Verdict, tr.Err)
	}
}

func TestNoDialler(t *testing.T) {
	t.Parallel()
	tr := probe.RunTrial(context.Background(), strategy.Strategy{},
		probe.Target{Host: "discord.com"}, 1, probe.TrialOptions{})
	if tr.Verdict != probe.VerdictLocalError {
		t.Fatalf("verdict = %s, want LOCAL-ERROR", tr.Verdict)
	}
}

func TestInvalidTargetIsLocalError(t *testing.T) {
	t.Parallel()
	for _, tg := range []probe.Target{
		{},
		{Host: "discord.com", Port: 70000},
		{Host: "discord.com", Addr: "not-an-ip"},
	} {
		tr := probe.RunTrial(context.Background(), strategy.Strategy{}, tg, 1,
			probe.TrialOptions{Dial: errDialer{err: errors.New("must not dial")}})
		if tr.Verdict != probe.VerdictLocalError {
			t.Errorf("%+v: verdict = %s, want LOCAL-ERROR", tg, tr.Verdict)
		}
	}
}

// The shipped Wrap is emit.NewSockTransport. A dialler that hands back anything
// else must be refused: silently skipping the desync would report a strategy
// that never ran.
func TestDefaultWrapRefusesANonSocket(t *testing.T) {
	t.Parallel()
	tr := probe.RunTrial(context.Background(), strategy.Strategy{},
		probe.Target{Host: "discord.com"}, 1, probe.TrialOptions{Dial: plainDialer{}})

	if tr.Verdict != probe.VerdictLocalError {
		t.Fatalf("verdict = %s (%s), want LOCAL-ERROR", tr.Verdict, tr.Err)
	}
}

// A cancelled parent context must end the trial rather than hanging on a
// socket that is still open.
func TestCancelledContext(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tr := probe.RunTrial(ctx, mustSpec(t, ""), probe.Target{Host: "cloudflare.com"}, 1, l.options(t))
	if tr.Verdict == probe.VerdictPass {
		t.Fatalf("verdict = PASS on a cancelled context")
	}
}

func TestVerdictNames(t *testing.T) {
	t.Parallel()
	cases := map[probe.Verdict]struct {
		name     string
		scorable bool
	}{
		probe.VerdictUnknown:       {"UNKNOWN", false},
		probe.VerdictPass:          {"PASS", true},
		probe.VerdictReset:         {"RESET", true},
		probe.VerdictTimeout:       {"TIMEOUT", true},
		probe.VerdictBlockPage:     {"BLOCKPAGE", true},
		probe.VerdictHandshakeFail: {"HANDSHAKE-FAIL", false},
		probe.VerdictDialFail:      {"DIAL-FAIL", false},
		probe.VerdictLocalError:    {"LOCAL-ERROR", false},
		probe.VerdictControlDown:   {"CONTROL-DOWN", false},
	}
	for v, want := range cases {
		if got := v.String(); got != want.name {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, got, want.name)
		}
		if got := v.Scorable(); got != want.scorable {
			t.Errorf("%s.Scorable() = %v, want %v", want.name, got, want.scorable)
		}
	}
	if got := probe.Verdict(99).String(); got != "INVALID" {
		t.Errorf("out-of-range verdict = %q", got)
	}
}

// Latency is what tells a ~22 ms injected RST (MEASUREMENTS.md §6) from a real
// origin that is simply slow, so it has to be recorded on the failure paths too.
func TestLatencyIsRecordedOnFailure(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026("discord.com"))
	tr := probe.RunTrial(context.Background(), mustSpec(t, ""),
		probe.Target{Host: "discord.com"}, 1, l.options(t))

	if tr.Verdict != probe.VerdictReset {
		t.Fatalf("verdict = %s", tr.Verdict)
	}
	if tr.Latency <= 0 {
		t.Error("Latency must be recorded on a failed trial")
	}
	if tr.At.IsZero() {
		t.Error("At must be recorded")
	}
}

// A clock seam is what lets the runner above this replay a session; without it
// every trial would stamp itself from the wall clock.
func TestNowSeam(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	tr := probe.RunTrial(context.Background(), strategy.Strategy{},
		probe.Target{Host: "discord.com"}, 1,
		probe.TrialOptions{
			Dial: errDialer{err: errors.New("nope")},
			Now:  func() time.Time { return fixed },
		})
	if !tr.At.Equal(fixed) {
		t.Errorf("At = %s, want %s", tr.At, fixed)
	}
}

// A censor that answers 443 with plain HTTP is a block page, not a TLS endpoint,
// and must not be reported as a handshake failure of the origin.
func TestNonTLSAnswerIsBlockPage(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
	}()
	t.Cleanup(func() { <-done })

	tr := probe.RunTrial(context.Background(), strategy.Strategy{},
		probe.Target{Host: "discord.com", Addr: "127.0.0.1", Port: portOf(t, ln)}, 1,
		probe.TrialOptions{Dial: pinnedDialer{}, Timeout: 2 * time.Second})

	if tr.Verdict != probe.VerdictBlockPage {
		t.Fatalf("verdict = %s (%s), want BLOCKPAGE", tr.Verdict, tr.Err)
	}
}

// pinnedDialer connects straight to a target's pinned address with no model in
// the way. It is the smallest dialler that still produces a real *net.TCPConn,
// so the shipped Wrap — emit.NewSockTransport — is what gets exercised.
type pinnedDialer struct{}

func (pinnedDialer) DialTCP(_ context.Context, t flow.Target) (net.Conn, error) {
	if !t.Addr.IsValid() {
		return nil, errors.New("probe test: pinnedDialer needs a pinned address")
	}
	return net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(t.Addr))
}

func portOf(t *testing.T, ln net.Listener) int {
	t.Helper()
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T", ln.Addr())
	}
	return ta.Port
}
