package testcensor

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// TestFragileRejectsSplitHandshake is MEASUREMENTS.md §5 restated as a test:
// www.yapikredi.com.tr answers a record-split ClientHello with
// "remote error: tls: illegal parameter". Splitting a handshake message across
// records is legal per RFC 8446 §5.1 and this terminator rejects it anyway,
// which is why desync cannot be applied unconditionally.
func TestFragileRejectsSplitHandshake(t *testing.T) {
	o := newOrigin(t, "www.yapikredi.com.tr")
	b := New(Fragile(), Options{Port: 443})
	c := dialThrough(t, b, o)

	hello := clientHello(t, "www.yapikredi.com.tr")
	sniStart, sniEnd := sniExtent(t, hello)

	err := handshake(t, c, o, "www.yapikredi.com.tr", (sniStart+sniEnd)/2)
	if err == nil {
		t.Fatal("a fragile terminator accepted a two-record handshake")
	}
	// MEASUREMENTS.md §5 records the client-side text verbatim:
	// "www.yapikredi.com.tr  handshake: remote error: tls: illegal parameter".
	// crypto/tls surfaces a RECEIVED alert as an opaque wrapped error rather
	// than a tls.AlertError, so the text is the assertion, and it is also the
	// exact string the measurement captured.
	if got := err.Error(); !strings.Contains(got, "remote error: tls: illegal parameter") {
		t.Fatalf("error = %q, want the measured illegal-parameter alert", got)
	}
}

// TestFragileAcceptsPlainHandshake is the other half of §5.2 and the reason the
// default policy is default-direct: a bank is not blocked, so a plain first
// attempt always works and it is never desynced.
func TestFragileAcceptsPlainHandshake(t *testing.T) {
	for _, m := range []Model{Fragile(), FragileEOF(), FragileReset()} {
		o := newOrigin(t, "www.akbank.com")
		b := New(m, Options{Port: 443})
		c := dialThrough(t, b, o)
		if err := handshake(t, c, o, "www.akbank.com"); err != nil {
			t.Fatalf("%s: plain handshake failed: %v", m.Name, err)
		}
		for _, f := range b.Flows() {
			if f.Verdict.Blocked() {
				t.Fatalf("%s: plain flow was blocked: %v", m.Name, f.Verdict)
			}
		}
	}
}

// TestFragileFailureShapes covers the three shapes §5 measured across the ten
// regressors: an alert (yapikredi), an EOF (six hosts) and a reset (three).
//
// The reset row is the trap. A reset before any server byte is exactly what the
// ladder escalates on, so a fragile bank is indistinguishable from a censored
// host on attempt 1 — which is why the ladder must try plain first and cache
// "plain works" durably rather than relying on a shipped exclusion list.
func TestFragileFailureShapes(t *testing.T) {
	cases := []struct {
		model Model
		check func(t *testing.T, err error)
	}{
		{Fragile(), func(t *testing.T, err error) {
			if !strings.Contains(err.Error(), "illegal parameter") {
				t.Fatalf("want an illegal-parameter alert, got %v", err)
			}
		}},
		{FragileEOF(), func(t *testing.T, err error) {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("want EOF, got %v", err)
			}
		}},
		{FragileReset(), func(t *testing.T, err error) {
			if !IsReset(err) {
				t.Fatalf("want ECONNRESET, got %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.model.Name, func(t *testing.T) {
			o := newOrigin(t, "www.isbank.com.tr")
			b := New(tc.model, Options{Port: 443})
			c := dialThrough(t, b, o)
			hello := clientHello(t, "www.isbank.com.tr")
			sniStart, sniEnd := sniExtent(t, hello)
			err := handshake(t, c, o, "www.isbank.com.tr", (sniStart+sniEnd)/2)
			if err == nil {
				t.Fatal("split handshake succeeded")
			}
			tc.check(t, err)
		})
	}
}

// TestFragileBlocksNothingByName is the property that makes Fragile a
// compatibility model rather than a censorship model. §5.1 measured every
// fragile host reachable plain, 20/20.
func TestFragileBlocksNothingByName(t *testing.T) {
	m := Fragile()
	if len(m.Blocked) != 0 {
		t.Fatalf("Fragile blocks %v; it must block nothing by name", m.Blocked)
	}
	for _, name := range append([]string{"discord.com"}, FragileTR...) {
		if v := feed(m, clientHello(t, name)); v.Blocked() {
			t.Errorf("%s: plain hello was blocked: %v", name, v)
		}
	}
}

// TestFragileRejectsOOB covers §5.1's harshest row: oob-at-1 and oob-at-3 left
// 0 of 20 fragile-host attempts working. It is the last ladder rung for a
// reason.
func TestFragileRejectsOOB(t *testing.T) {
	in := Fragile().Inspect(443)
	if v := in.ClientOOB([]byte{0xff}); !v.Blocked() {
		t.Fatalf("an urgent byte must break this terminator: %v", v)
	}
}

// TestFragileTRList pins the ten measured regressors and, just as importantly,
// the four hosts that were NOT fragile. Shipping a bank as fragile when it is
// not costs the user a bypass they could have had.
func TestFragileTRList(t *testing.T) {
	if len(FragileTR) != 10 {
		t.Fatalf("FragileTR has %d entries, §5 measured exactly 10", len(FragileTR))
	}
	got := strings.Join(FragileTR, " ")
	for _, notFragile := range []string{"garantibbva", "qnbfinansbank", "teb.com.tr", "nvi.gov.tr"} {
		if strings.Contains(got, notFragile) {
			t.Errorf("%s is listed but §5 measured it as NOT fragile", notFragile)
		}
	}
}

// TestFragileSpanningDetectionIsFramingNotContent pins that the predicate looks
// at how the handshake was framed, not at what it says. A single record carrying
// the identical bytes must pass.
func TestFragileSpanningDetectionIsFramingNotContent(t *testing.T) {
	hello := clientHello(t, "www.gib.gov.tr")
	sniStart, sniEnd := sniExtent(t, hello)

	if v := feed(Fragile(), hello); v.Blocked() {
		t.Fatalf("one record was rejected: %v", v)
	}
	if v := feed(Fragile(), split(t, hello, (sniStart+sniEnd)/2)); !v.Blocked() {
		t.Fatalf("two records were accepted: %v", v)
	}
	// The decision must wait for the first record to complete rather than firing
	// on a prefix: a slow client is not a fragile-handshake violation.
	in := Fragile().Inspect(443)
	if v, _ := in.Client(hello[:20], 0); v.Blocked() {
		t.Fatalf("decided on a 20-byte prefix: %v", v)
	}
}

// TestMiddleboxAlertReachesClientBeforeReset pins the byte order: the alert must
// be readable, then the connection dies. A client that only ever sees the reset
// cannot report "illegal parameter" and the operator loses the one diagnostic
// that names the cause.
func TestMiddleboxAlertReachesClientBeforeReset(t *testing.T) {
	o := newOrigin(t, "www.yapikredi.com.tr")
	b := New(Fragile(), Options{Port: 443})
	c, err := b.DialContext(context.Background(), "tcp", o.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	hello := clientHello(t, "www.yapikredi.com.tr")
	sniStart, sniEnd := sniExtent(t, hello)
	if _, err := c.Write(split(t, hello, (sniStart+sniEnd)/2)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 7)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read alert: %v", err)
	}
	want := AlertRecord(AlertIllegalParameter)
	if string(got) != string(want) {
		t.Fatalf("alert record = % x, want % x", got, want)
	}
	if _, err := c.Read(make([]byte, 1)); !IsReset(err) {
		t.Fatalf("after the alert: %v, want ECONNRESET", err)
	}
}

// TestReassemblingModelWaitsForTheWholeHandshake is the regression guard for a
// model that would otherwise be defeated by its own impatience: a censor that
// reassembles records must not conclude "no hostname here" from record 1 alone,
// or every reframing emitter would appear to beat it.
func TestReassemblingModelWaitsForTheWholeHandshake(t *testing.T) {
	m := TT2026()
	m.FirstRecordOnly = false // the stronger, record-reassembling censor
	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	two := split(t, hello, (sniStart+sniEnd)/2)

	h, _ := tlsmsg.ParseHeader(two)
	rec1 := two[:5+h.Length]

	in := m.Inspect(443)
	if v, _ := in.Client(rec1, 0); v.Blocked() || in.Decided() {
		t.Fatalf("decided on record 1 alone: %v", in.Verdict())
	}
	if v, _ := in.Client(two[len(rec1):], 0); !v.Blocked() {
		t.Fatalf("reassembly did not recover the hostname: %v", v)
	}

	// Against a fragile terminator the same two records must still be rejected
	// once both have arrived.
	fin := Fragile().Inspect(443)
	if v, _ := fin.Client(rec1, 0); v.Blocked() {
		t.Fatalf("fragile decided on record 1 alone: %v", v)
	}
	if v, _ := fin.Client(two[len(rec1):], 0); !v.Blocked() {
		t.Fatalf("fragile accepted a two-record handshake: %v", v)
	}

	// And a cut so early that record 1 cannot hold even the handshake header
	// must still be recognised as spanning.
	tiny := split(t, hello, 1)
	if v := feed(Fragile(), tiny); !v.Blocked() {
		t.Fatalf("a 1-byte first record was accepted: %v", v)
	}
}
