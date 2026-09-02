package ops

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/httpmsg"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// allCaps is a transport that can do everything, so a capability gate never
// fires before the behaviour under test.
const allCaps = strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL |
	strategy.CapOOB | strategy.CapUDPTTL | strategy.CapRawInject

// The geometry of MEASUREMENTS.md §3.2: a ClientHello whose record body is 1497
// bytes with the SNI hostname at [112,122). Every cut-position expectation in
// this file is stated against these exact numbers, which is why the fixture
// asserts them rather than merely producing something hello-shaped.
const (
	ttBodyLen  = 1497
	ttSNIStart = 112
	ttSNIEnd   = 122
	ttHost     = "discord.gg" // 10 bytes: exactly sniEnd-sniStart
)

// fillerExt is an unassigned extension type used to position the server_name
// extension inside a fixture. It is deliberately NOT the padding extension:
// tlspad refuses a hello that already carries one, and a fixture that tripped
// that check would test the fixture rather than the op.
const fillerExt uint16 = 0x1a1a

// helloAt builds a genuine ClientHello whose server_name hostname starts at
// body offset sniStart inside a record body of bodyLen bytes. It is checked
// against tlsmsg.Parse, so the coordinates a test reasons about are the ones
// the implementation will actually compute.
func helloAt(tb testing.TB, name string, sniStart, bodyLen int) []byte {
	tb.Helper()
	const fixed = 47 // handshake header, version, random, session id, ciphers, compression, ext length
	const sniOverhead = 9

	lead := sniStart - fixed - sniOverhead
	tail := bodyLen - fixed - lead - sniOverhead - len(name)
	if lead < extHdrLen || (tail != 0 && tail < extHdrLen) {
		tb.Fatalf("helloAt(%q, %d, %d): impossible geometry (lead %d, tail %d)", name, sniStart, bodyLen, lead, tail)
	}

	ext := func(typ uint16, n int) []byte {
		b := make([]byte, n)
		binary.BigEndian.PutUint16(b[0:2], typ)
		binary.BigEndian.PutUint16(b[2:4], uint16(n-extHdrLen))
		return b
	}
	sni := []byte{0x00, 0x00}
	sni = binary.BigEndian.AppendUint16(sni, uint16(5+len(name))) // extension length
	sni = binary.BigEndian.AppendUint16(sni, uint16(3+len(name))) // server name list length
	sni = append(sni, 0x00)                                       // name type: host_name
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)

	exts := append(ext(fillerExt, lead), sni...)
	if tail > 0 {
		exts = append(exts, ext(fillerExt, tail)...)
	}

	body := []byte{0x01, 0, 0, 0} // handshake header; length patched below
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // one compression method
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	msgLen := len(body) - 4
	body[1], body[2], body[3] = byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)

	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(body)))
	rec = append(rec, body...)

	m := tlsmsg.Parse(rec, 443)
	switch {
	case m.Proto != tlsmsg.ProtoTLS || !m.Complete:
		tb.Fatalf("fixture does not parse as a complete TLS message: %+v", m)
	case m.ServerName != name:
		tb.Fatalf("fixture server name = %q, want %q", m.ServerName, name)
	case m.BodyLen != bodyLen:
		tb.Fatalf("fixture body length = %d, want %d", m.BodyLen, bodyLen)
	case m.SNIStart != sniStart || m.SNIEnd != sniStart+len(name):
		tb.Fatalf("fixture SNI at [%d,%d), want [%d,%d)", m.SNIStart, m.SNIEnd, sniStart, sniStart+len(name))
	}
	return rec
}

// ttHello is MEASUREMENTS.md §3.2's exact fixture.
func ttHello(tb testing.TB) ([]byte, tlsmsg.Meta) {
	tb.Helper()
	b := helloAt(tb, ttHost, ttSNIStart, ttBodyLen)
	return b, tlsmsg.Parse(b, 443)
}

func httpFixture(host string) ([]byte, tlsmsg.Meta) {
	req := []byte("GET /api/v9/gateway HTTP/1.1\r\nHost: " + host + "\r\nAccept: */*\r\n\r\n")
	return req, tlsmsg.Parse(req, 80)
}

// quicFixture builds a QUIC v1 Initial datagram with a 8-byte DCID.
func quicFixture() ([]byte, tlsmsg.Meta) {
	d := []byte{0xc3}
	d = binary.BigEndian.AppendUint32(d, tlsmsg.QUICVersion1)
	d = append(d, 8)
	d = append(d, 1, 2, 3, 4, 5, 6, 7, 8) // DCID
	d = append(d, 4)
	d = append(d, 9, 9, 9, 9) // SCID
	d = append(d, 0x00)       // token length
	body := 1200 - len(d) - 2
	d = binary.BigEndian.AppendUint16(d, uint16(body)|0x4000)
	d = append(d, make([]byte, body)...)
	return d, tlsmsg.Parse(d, 443)
}

func buildSpec(tb testing.TB, spec string, payload []byte, m tlsmsg.Meta) (strategy.Plan, error) {
	tb.Helper()
	s, err := NewRegistry().Get(spec)
	if err != nil {
		return strategy.Plan{}, err
	}
	return s.Build(payload, m, allCaps, strategy.DefaultBudget())
}

func mustBuild(tb testing.TB, spec string, payload []byte, m tlsmsg.Meta) strategy.Plan {
	tb.Helper()
	p, err := buildSpec(tb, spec, payload, m)
	if err != nil {
		tb.Fatalf("build %q: %v", spec, err)
	}
	if !bytes.Equal(p.StreamBytes(), p.Payload) {
		tb.Fatalf("build %q: stream bytes do not reproduce the payload", spec)
	}
	return p
}

// censor runs a plan past a modelled middlebox exactly as the sender would emit
// it, and reports the verdict.
func censor(m testcensor.Model, port int, p strategy.Plan) testcensor.Verdict {
	in := m.Inspect(port)
	for _, s := range p.Segments {
		if s.Kind == strategy.SegOOBByte {
			in.ClientOOB(s.Data)
			continue
		}
		in.Client(s.Data, s.TTL)
	}
	return in.Verdict()
}

// censorBytes runs a raw byte string past a middlebox as a single segment.
func censorBytes(m testcensor.Model, port int, b []byte) testcensor.Verdict {
	in := m.Inspect(port)
	in.Client(b, 0)
	return in.Verdict()
}

// TestTLSFragRefusesCutAtOrAfterSNIEnd is the point of the whole design.
//
// It walks all ten cut positions MEASUREMENTS.md §3.2 measured, at that
// section's exact geometry (body=1497, SNI at [112,122)), and asserts two
// things for each: that the emitter's verdict matches the measurement, and that
// the measurement itself is reproduced by testcensor.TT2026 on the bytes that
// cut would have produced. The second half is what proves the validator is not
// merely conservative — every position it refuses really is one the DPI still
// matches, and every position it accepts really does get through.
func TestTLSFragRefusesCutAtOrAfterSNIEnd(t *testing.T) {
	payload, meta := ttHello(t)
	model := testcensor.TT2026(ttHost)

	// Row 1 of §3.2: no cut at all is blocked 0/3. Without it, "the emitter
	// passes" would prove nothing about the model.
	if v := censorBytes(model, 443, payload); !v.Blocked() {
		t.Fatalf("baseline: unfragmented hello was not blocked: %v", v)
	}

	cases := []struct {
		pos     string
		emit    bool // the emitter accepts the cut
		through bool // §3.2's measured column: the flow gets through
	}{
		{"snistart-20", true, true},
		{"snistart-1", true, true},
		{"snistart", true, true},
		{"snistart+1", true, true},
		{"snimid", true, true},
		{"sniend-1", true, true},
		{"sniend", false, false},
		{"sniend+1", false, false},
		{"sniend+20", false, false},
		{"sniend+200", false, false},
	}
	for _, c := range cases {
		t.Run(c.pos, func(t *testing.T) {
			p, err := strategy.ParsePos(c.pos)
			if err != nil {
				t.Fatalf("ParsePos(%q): %v", c.pos, err)
			}
			cut, ok := p.Resolve(meta)
			if !ok {
				t.Fatalf("pos %s does not resolve", c.pos)
			}

			// What the censor model does with the bytes this cut produces,
			// whether or not the emitter is willing to produce them.
			raw, err := tlsmsg.SplitRecord(payload, []int{cut})
			if err != nil {
				t.Fatalf("SplitRecord at %d: %v", cut, err)
			}
			if got := !censorBytes(model, 443, raw).Blocked(); got != c.through {
				t.Errorf("TT2026 on a cut at %s (offset %d): through=%v, MEASUREMENTS.md §3.2 says %v",
					c.pos, cut, got, c.through)
			}

			plan, err := buildSpec(t, "tlsfrag:pos="+c.pos, payload, meta)
			if !c.emit {
				if !errors.Is(err, strategy.ErrCutAfterSNI) {
					t.Fatalf("cut at %s (offset %d, sniEnd=%d) must be refused with ErrCutAfterSNI, got %v",
						c.pos, cut, meta.SNIEnd, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("cut at %s (offset %d) must be accepted: %v", c.pos, cut, err)
			}
			if !bytes.Equal(plan.StreamBytes(), raw) {
				t.Errorf("cut at %s: plan bytes differ from tlsmsg.SplitRecord's", c.pos)
			}
			if v := censor(model, 443, plan); v.Blocked() {
				t.Errorf("cut at %s: the emitted plan was blocked: %v", c.pos, v)
			}
		})
	}
}

// TestTLSFragEmitsTwoRecordsInOneWrite encodes MEASUREMENTS.md §3.1: tlsrec2-1seg
// — two records inside a SINGLE TCP segment — passed 3/3 while every two-segment
// TCP split failed. The emitter therefore needs no timing, no socket option and
// no root, and one write is a load-bearing property, not an optimisation.
func TestTLSFragEmitsTwoRecordsInOneWrite(t *testing.T) {
	payload, meta := ttHello(t)
	p := mustBuild(t, "tlsfrag:pos=snimid", payload, meta)

	if p.WriteCount() != 1 {
		t.Fatalf("WriteCount = %d, want 1 (MEASUREMENTS.md §3.1)", p.WriteCount())
	}
	if p.Caps() != strategy.CapStreamWrite {
		t.Errorf("Caps = %s, want just streamwrite: one write needs nothing else", p.Caps())
	}
	b := p.Segments[0].Data
	first, ok := tlsmsg.ParseHeader(b)
	if !ok {
		t.Fatal("first record header does not parse")
	}
	second, ok := tlsmsg.ParseHeader(b[5+first.Length:])
	if !ok {
		t.Fatal("second record header does not parse")
	}
	cut := ttSNIStart + (ttSNIEnd-ttSNIStart)/2
	if first.Length != cut {
		t.Errorf("first record body = %d, want the cut offset %d", first.Length, cut)
	}
	if first.Length+second.Length != ttBodyLen {
		t.Errorf("record bodies sum to %d, want the original %d", first.Length+second.Length, ttBodyLen)
	}
	if first.Type != second.Type || first.Version != second.Version {
		t.Error("the second record does not reuse the original type and version")
	}
	if len(b) != len(payload)+5 {
		t.Errorf("plan is %d bytes, want the payload plus one 5-byte record header", len(b))
	}
}

// TestSNIMidIsStrictlyDominant encodes MEASUREMENTS.md §3.3's claim that snimid
// is the right default: it satisfies the record rule AND splits the hostname
// itself, so it also defeats a DPI that string-matches the reassembled stream.
// snistart-20 satisfies only the record rule.
func TestSNIMidIsStrictlyDominant(t *testing.T) {
	payload, meta := ttHello(t)
	tt, naive := testcensor.TT2026(ttHost), testcensor.Naive(ttHost)

	mid := mustBuild(t, "tlsfrag:pos=snimid", payload, meta)
	if v := censor(tt, 443, mid); v.Blocked() {
		t.Errorf("snimid must evade the measured DPI: %v", v)
	}
	if v := censor(naive, 443, mid); v.Blocked() {
		t.Errorf("snimid must also evade a naive substring matcher: %v", v)
	}

	early := mustBuild(t, "tlsfrag:pos=snistart-20", payload, meta)
	if v := censor(tt, 443, early); v.Blocked() {
		t.Errorf("snistart-20 must evade the measured DPI (§3.2 measured it 3/3): %v", v)
	}
	if v := censor(naive, 443, early); !v.Blocked() {
		t.Error("snistart-20 leaves the hostname contiguous, so a naive matcher must still catch it")
	}
}

// TestTLSFragOnAHelloWithoutSNI: the rule has nothing to say when there is no
// hostname, but the op still requires one — a cut chosen to hide a name that is
// not there is a strategy operating on a message it did not parse.
func TestTLSFragNeedsSNI(t *testing.T) {
	payload := helloAt(t, "example.org", 200, 900)
	m := tlsmsg.Parse(payload, 443)
	m.SNIStart, m.SNIEnd, m.ServerName = -1, -1, "" // as if the walk had found nothing

	_, err := buildSpec(t, "tlsfrag:pos=snimid", payload, m)
	if !errors.Is(err, strategy.ErrNeedSNI) {
		t.Fatalf("err = %v, want ErrNeedSNI", err)
	}
	// Even an absolute cut is refused: tlsfrag exists to hide a hostname, and a
	// strategy that cannot know whether it did is not a bypass, it is a guess.
	if _, err := buildSpec(t, "tlsfrag:pos=64", payload, m); !errors.Is(err, strategy.ErrNeedSNI) {
		t.Fatalf("err = %v, want ErrNeedSNI for an absolute cut too", err)
	}
	// tlsevery does not read the SNI extent, so it applies — and with no
	// hostname in the record there is nothing for the §3.2 rule to refuse.
	if _, err := buildSpec(t, "tlsevery:period=64", payload, m); err != nil {
		t.Fatalf("tlsevery on a hello with no SNI: %v", err)
	}
}

func TestTLSFragNeedsCompleteMessage(t *testing.T) {
	payload, _ := ttHello(t)
	truncated := payload[:600]
	m := tlsmsg.Parse(truncated, 443)
	m.Truncated = true
	if m.Complete {
		t.Fatal("fixture precondition: a 600-byte prefix must not parse as complete")
	}
	// The SNI is inside the prefix, so only the completeness gate can refuse.
	if !m.HasSNI() {
		t.Fatal("fixture precondition: the hostname must be inside the prefix")
	}
	if _, err := buildSpec(t, "tlsfrag:pos=snimid", truncated, m); !errors.Is(err, strategy.ErrNeedComplete) {
		t.Fatalf("err = %v, want ErrNeedComplete", err)
	}
}

func TestTLSFragRequiresPos(t *testing.T) {
	if _, err := NewRegistry().Get("tlsfrag"); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatalf("err = %v, want ErrBadValue naming the missing pos", err)
	}
	if _, err := NewRegistry().Get("tlsfrag:pos=sideways"); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatalf("err = %v, want ErrBadValue for an unparseable pos", err)
	}
}

// TestTLSEveryFirstRecordLimit is the §3 half of the same rule: the first
// record ends at `period`, so tlsrec-every-16 and -every-64 pass (16 and 64 are
// both at or below sniEnd-1 = 121) and tlsrec-every-256 fails. One predicate,
// three measured points, and the periodic emitter needs no separate validator.
func TestTLSEveryFirstRecordLimit(t *testing.T) {
	payload, meta := ttHello(t)
	model := testcensor.TT2026(ttHost)

	for _, period := range []int{16, 64} {
		spec := fmt.Sprintf("tlsevery:period=%d", period)
		p := mustBuild(t, spec, payload, meta)
		if p.WriteCount() != 1 {
			t.Errorf("%s: WriteCount = %d, want 1", spec, p.WriteCount())
		}
		h, _ := tlsmsg.ParseHeader(p.Segments[0].Data)
		if h.Length != period {
			t.Errorf("%s: first record body = %d, want %d", spec, h.Length, period)
		}
		if v := censor(model, 443, p); v.Blocked() {
			t.Errorf("%s: blocked, but MEASUREMENTS.md §3 measured every-%d at 3/3: %v", spec, period, v)
		}
	}

	// 128 is the untested midpoint the probe ladder sweeps and 256 is measured
	// 0/3. Both put the first record's end past sniEnd-1 = 121, so both are
	// refused by the same predicate.
	for _, period := range []int{128, 256} {
		spec := fmt.Sprintf("tlsevery:period=%d", period)
		if _, err := buildSpec(t, spec, payload, meta); !errors.Is(err, strategy.ErrCutAfterSNI) {
			t.Errorf("%s: err = %v, want ErrCutAfterSNI (limit is sniEnd-1 = %d)", spec, err, ttSNIEnd-1)
		}
	}
}

func TestTLSEveryRejectsUselessPeriods(t *testing.T) {
	payload, meta := ttHello(t)
	if _, err := NewRegistry().Get("tlsevery"); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatalf("err = %v, want ErrBadValue naming the missing period", err)
	}
	if _, err := NewRegistry().Get("tlsevery:period=0"); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatalf("err = %v, want ErrBadValue for period=0", err)
	}
	// A period at or past the body length moves no boundary: refused, never a
	// silent no-op wearing the strategy's name.
	if _, err := buildSpec(t, "tlsevery:period=2000", payload, meta); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatalf("err = %v, want ErrBadValue for a period larger than the record", err)
	}
}

// TestChunkStaysInsideTheSegmentBudget: the budget is a safety cap (DOSSIER §3,
// and the guard against the XNU small-write panic), so chunk covers the head of
// the message and puts the remainder in one write rather than demanding 126.
func TestChunkStaysInsideTheSegmentBudget(t *testing.T) {
	payload, meta := ttHello(t)
	bud := strategy.DefaultBudget()

	for _, size := range []int{1, 2, 4, 12, 40} {
		spec := fmt.Sprintf("chunk:size=%d", size)
		p := mustBuild(t, spec, payload, meta)
		if p.WriteCount() > bud.MaxSegments {
			t.Errorf("%s: %d writes, budget is %d", spec, p.WriteCount(), bud.MaxSegments)
		}
		if p.WriteCount() != bud.MaxSegments {
			t.Errorf("%s: %d writes, want the budget filled", spec, p.WriteCount())
		}
		for i, s := range p.Segments[:p.WriteCount()-1] {
			if len(s.Data) != size {
				t.Errorf("%s: segment %d is %d bytes, want %d", spec, i, len(s.Data), size)
			}
		}
		if p.Caps() != strategy.CapStreamWrite|strategy.CapNoDelay {
			t.Errorf("%s: Caps = %s, want nodelay for a multi-write plan", spec, p.Caps())
		}
		if len(p.Notes) == 0 {
			t.Errorf("%s: the truncated geometry must be recorded in the plan", spec)
		}
	}

	// A short message chunks completely and needs no note.
	short, sm := httpFixture("discord.com")
	p := mustBuild(t, "chunk:size=12", short, sm)
	if want := (len(short) + 11) / 12; p.WriteCount() != want {
		t.Errorf("short message: %d writes, want %d", p.WriteCount(), want)
	}
	if len(p.Notes) != 0 {
		t.Errorf("short message: unexpected notes %v", p.Notes)
	}
}

func TestChunkRejectsAnInertSize(t *testing.T) {
	payload, meta := httpFixture("discord.com")
	if _, err := buildSpec(t, fmt.Sprintf("chunk:size=%d", len(payload)), payload, meta); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatal("a chunk size covering the whole message moves nothing and must be refused")
	}
	if _, err := NewRegistry().Get("chunk"); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatal("chunk must require size")
	}
}

// TestChunkDoesNotEvadeTT2026 is an honest negative. MEASUREMENTS.md §3.4
// measured chunk-4 and chunk-12 through 3/3 on the real line, but §3.1 also
// measured that this DPI reassembles TCP, and no rule explains the chunk curve.
// The model reproduces the mechanism, not the lookup table, so under it
// chunking is a non-bypass — and a test that pretended otherwise would be
// scoring the code against one afternoon in Kayseri.
func TestChunkDoesNotEvadeTT2026(t *testing.T) {
	payload, meta := ttHello(t)
	for _, spec := range []string{"chunk:size=4", "chunk:size=12", "split:pos=1", "split:pos=snimid"} {
		p := mustBuild(t, spec, payload, meta)
		if v := censor(testcensor.TT2026(ttHost), 443, p); !v.Blocked() {
			t.Errorf("%s: evaded a TCP-reassembling middlebox, which §3.1 says is impossible", spec)
		}
	}
}

func TestSplitShape(t *testing.T) {
	payload, meta := ttHello(t)
	p := mustBuild(t, "split:pos=3", payload, meta)
	if p.WriteCount() != 2 || len(p.Segments[0].Data) != 3 {
		t.Fatalf("split:pos=3 produced %d writes, first %d bytes", p.WriteCount(), len(p.Segments[0].Data))
	}

	// An anchor that cannot resolve is an explicit failure. A silent zero here
	// is a one-byte split, measured 0/5, that looks like a working strategy.
	http, hm := httpFixture("discord.com")
	if _, err := buildSpec(t, "split:pos=snimid", http, hm); !errors.Is(err, strategy.ErrNeedSNI) {
		t.Fatalf("err = %v, want ErrNeedSNI for an SNI anchor on a plaintext request", err)
	}
	if _, err := NewRegistry().Get("split"); !errors.Is(err, strategy.ErrBadValue) {
		t.Fatal("split must require pos")
	}
}

func TestDisorderSetsTheLeadingSegmentTTL(t *testing.T) {
	payload, meta := ttHello(t)
	p := mustBuild(t, "disorder:pos=3,ttl=2", payload, meta)
	if p.WriteCount() != 2 {
		t.Fatalf("WriteCount = %d, want 2", p.WriteCount())
	}
	if p.Segments[0].TTL != 2 || p.Segments[1].TTL != 0 {
		t.Fatalf("TTLs = %d,%d, want 2,0", p.Segments[0].TTL, p.Segments[1].TTL)
	}
	if !p.Caps().Has(strategy.CapSockTTL) {
		t.Error("a plan with a per-segment TTL must declare sockttl")
	}

	// Without the capability the strategy refuses to load. Emitting the head at
	// the default TTL would be a plain split — measured 0/5 — wearing
	// disorder's name.
	s, err := NewRegistry().Get("disorder:pos=3")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Build(payload, meta, strategy.CapStreamWrite|strategy.CapNoDelay, strategy.DefaultBudget())
	if !errors.Is(err, strategy.ErrCapUnavailable) {
		t.Fatalf("err = %v, want ErrCapUnavailable", err)
	}
}

// TestDisorderAndOOBAreMutuallyExclusive: zapret gates the pair to Linux and
// byedpi's --disoob measures 0/8 on macOS against 8/8 for --oob alone.
func TestDisorderAndOOBAreMutuallyExclusive(t *testing.T) {
	_, err := NewRegistry().Get("disorder:pos=3|oob:pos=1")
	if !errors.Is(err, strategy.ErrIncompatible) {
		t.Fatalf("err = %v, want ErrIncompatible", err)
	}
	if !strings.Contains(err.Error(), "darwin") {
		t.Errorf("the refusal must say why on this platform: %v", err)
	}
}

func TestOOBByteIsNotPartOfTheStream(t *testing.T) {
	payload, meta := ttHello(t)
	p := mustBuild(t, "oob:pos=1,junk=97", payload, meta)

	if p.WriteCount() != 3 {
		t.Fatalf("WriteCount = %d, want head + oob + tail", p.WriteCount())
	}
	if p.Segments[1].Kind != strategy.SegOOBByte || p.Segments[1].Data[0] != 'a' {
		t.Fatalf("segment 1 = %s %v, want an OOB 'a'", p.Segments[1].Kind, p.Segments[1].Data)
	}
	// mustBuild already asserted StreamBytes == Payload, which is the whole
	// claim: the junk byte never reaches the peer's reassembled stream.
	if !p.Caps().Has(strategy.CapOOB) {
		t.Error("a plan with an OOB segment must declare oob")
	}

	// §3 measured oob-at-1 through 3/3: the middlebox sees the byte inline, so
	// its record parse is shifted and the hostname is never found.
	if v := censor(testcensor.TT2026(ttHost), 443, p); v.Blocked() {
		t.Errorf("oob:pos=1 must evade a middlebox that reads the urgent byte inline: %v", v)
	}
	// §5.1 measured it 0/20 against fragile endpoints. It is the last rung for
	// exactly this reason.
	if v := censor(testcensor.Fragile(), 443, p); !v.Blocked() {
		t.Error("oob must break a fragile terminator; if it does not, the model or the risk ranking is wrong")
	}
}

// TestFragileTerminatorForcesPlainFirst is MEASUREMENTS.md §5.2 as an
// executable claim: the primary emitter breaks 10 of 41 real Turkish hosts, all
// banks and .gov.tr, so connecting undesynced first is a correctness
// requirement and not an optimisation.
func TestFragileTerminatorForcesPlainFirst(t *testing.T) {
	payload, meta := ttHello(t)
	frag := mustBuild(t, "tlsfrag:pos=snimid", payload, meta)
	if v := censor(testcensor.Fragile(), 443, frag); !v.Blocked() {
		t.Error("a terminator that rejects a spanning handshake must reject tlsfrag")
	}
	plain := mustBuild(t, "", payload, meta)
	if v := censor(testcensor.Fragile(), 443, plain); v.Blocked() {
		t.Errorf("plain must reach every fragile host: %v", v)
	}
	if plain.WriteCount() != 1 || !bytes.Equal(plain.Segments[0].Data, payload) {
		t.Error("plain must emit the first message unmodified in one write")
	}
}

func TestHostMutators(t *testing.T) {
	const host = "discord.com"
	tests := []struct {
		spec  string
		check func(t *testing.T, out []byte)
	}{
		{"hostcase", func(t *testing.T, out []byte) {
			if !bytes.Contains(out, []byte(httpmsg.DefaultSpell+": "+host)) {
				t.Errorf("header not respelled: %q", out)
			}
		}},
		{"hostspell:spell=HOST", func(t *testing.T, out []byte) {
			if !bytes.Contains(out, []byte("HOST: "+host)) {
				t.Errorf("header not respelled: %q", out)
			}
		}},
		{"hostdot", func(t *testing.T, out []byte) {
			if !bytes.Contains(out, []byte("Host: "+host+".\r\n")) {
				t.Errorf("root dot not appended: %q", out)
			}
		}},
		{"hostpad:len=64", func(t *testing.T, out []byte) {
			if !bytes.Contains(out, []byte(httpmsg.PadHeaderName+": ")) {
				t.Errorf("pad header not inserted: %q", out)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			payload, meta := httpFixture(host)
			p := mustBuild(t, tc.spec, payload, meta)
			tc.check(t, p.Payload)
			// Every mutator must leave a request the origin can still parse,
			// and must have reparsed so a later op indexes the new bytes.
			r, err := httpmsg.Parse(p.Payload)
			if err != nil || !r.Complete || !r.HasHost() {
				t.Fatalf("mutated request no longer parses: %v %+v", err, r)
			}
			if bytes.Equal(p.Payload, payload) {
				t.Fatal("mutator produced identical bytes: an inert knob is the defect §3.5 records")
			}
		})
	}
}

func TestHostMutatorsRefuseWhenTheyWouldDoNothing(t *testing.T) {
	tls, tm := ttHello(t)
	for _, spec := range []string{"hostcase", "hostdot", "hostpad:len=64", "hostspell:spell=hoSt"} {
		if _, err := buildSpec(t, spec, tls, tm); !errors.Is(err, strategy.ErrNeedHost) {
			t.Errorf("%s on a TLS message: err = %v, want ErrNeedHost", spec, err)
		}
	}
	if _, err := NewRegistry().Get("hostspell:spell=xyzzy"); !errors.Is(err, strategy.ErrBadValue) {
		t.Error("a spelling that is not a case variant of \"host\" must be refused at parse time")
	}
	if _, err := NewRegistry().Get("hostpad:len=2"); !errors.Is(err, strategy.ErrBadValue) {
		t.Error("a pad smaller than one header line must be refused at parse time")
	}

	// An already-dotted host cannot be dotted again: refused, not silently
	// returned unchanged.
	payload, meta := httpFixture("discord.com.")
	if _, err := buildSpec(t, "hostdot", payload, meta); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("hostdot on an already-dotted host: err = %v, want ErrNotApplicable", err)
	}
	lit, lm := httpFixture("162.159.128.233")
	if _, err := buildSpec(t, "hostdot", lit, lm); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("hostdot on an IP-literal Host: err = %v, want ErrNotApplicable", err)
	}
	// Respelling a header that already carries that spelling changes nothing,
	// so it is refused rather than counted as an applied strategy.
	respelled := mustBuild(t, "hostcase", payload, meta).Payload
	_, err := buildSpec(t, "hostspell:spell="+httpmsg.DefaultSpell, respelled, tlsmsg.Parse(respelled, 80))
	if !errors.Is(err, ErrNotApplicable) {
		t.Errorf("respelling an already-respelled header: err = %v, want ErrNotApplicable", err)
	}
}

// TestHostMutatorsCompose: KindMutate ops run in Kind order before any
// schedule, and each reparses, so a chunk boundary lands on the mutated bytes.
func TestHostMutatorsCompose(t *testing.T) {
	payload, meta := httpFixture("discord.com")
	p := mustBuild(t, "chunk:size=12|hostdot|hostcase", payload, meta)
	if !bytes.Contains(p.Payload, []byte(httpmsg.DefaultSpell+": discord.com.")) {
		t.Fatalf("both mutators must apply: %q", p.Payload)
	}
	if len(p.Payload) != len(payload)+1 {
		t.Errorf("payload grew by %d bytes, want 1", len(p.Payload)-len(payload))
	}
	if p.Segments[0].Data[0] != 'G' || len(p.Segments[0].Data) != 12 {
		t.Error("the schedule must be laid over the mutated payload")
	}
}

func TestTLSPadPushesTheSNI(t *testing.T) {
	payload, meta := ttHello(t)
	p := mustBuild(t, "tlspad:to=600", payload, meta)

	m := tlsmsg.Parse(p.Payload, 443)
	if !m.Complete || m.ServerName != ttHost {
		t.Fatalf("padded hello does not parse: %+v", m)
	}
	if m.SNIStart != 600 {
		t.Fatalf("SNI at %d, want 600", m.SNIStart)
	}
	if m.BodyLen != ttBodyLen+(600-ttSNIStart) {
		t.Errorf("body = %d, want %d", m.BodyLen, ttBodyLen+(600-ttSNIStart))
	}
	if _, _, err := walkHelloExtensions(p.Payload[5 : 5+m.BodyLen]); err != nil {
		t.Fatalf("padded hello is not structurally walkable: %v", err)
	}

	// Composition is the point: after tlspad the cut positions a reframer
	// resolves are the PADDED ones, so the rule is enforced on the bytes that
	// will actually be written.
	comp := mustBuild(t, "tlspad:to=600|tlsfrag:pos=snimid", payload, meta)
	h, _ := tlsmsg.ParseHeader(comp.Segments[0].Data)
	if h.Length != 600+len(ttHost)/2 {
		t.Errorf("first record body = %d, want the padded snimid %d", h.Length, 600+len(ttHost)/2)
	}
	if v := censor(testcensor.TT2026(ttHost), 443, comp); v.Blocked() {
		t.Errorf("the padded, reframed hello must still evade: %v", v)
	}
}

func TestTLSPadRefusals(t *testing.T) {
	payload, meta := ttHello(t)

	if _, err := buildSpec(t, "tlspad:to=114", payload, meta); !errors.Is(err, strategy.ErrBadValue) {
		t.Error("a target less than one extension header past the SNI must be refused")
	}
	if _, err := buildSpec(t, "tlspad:to=16000", payload, meta); !errors.Is(err, strategy.ErrBadValue) {
		t.Error("padding past the 16384-byte record limit must be refused")
	}

	http, hm := httpFixture("discord.com")
	if _, err := buildSpec(t, "tlspad:to=600", http, hm); !errors.Is(err, strategy.ErrNeedSNI) {
		t.Error("tlspad on a plaintext request must be refused")
	}

	// A hello that already carries a padding extension is refused rather than
	// silently given a second one, which RFC 8446 §4.2 forbids.
	padded := mustBuild(t, "tlspad:to=300", payload, meta).Payload
	pm := tlsmsg.Parse(padded, 443)
	if _, err := buildSpec(t, "tlspad:to=600", padded, pm); !errors.Is(err, ErrAlreadyPadded) {
		t.Fatalf("err = %v, want ErrAlreadyPadded", err)
	}
}

func TestWalkHelloExtensionsRejectsMalformedHellos(t *testing.T) {
	payload, _ := ttHello(t)
	body := append([]byte(nil), payload[5:]...)

	if _, _, err := walkHelloExtensions(body); err != nil {
		t.Fatalf("the fixture must walk cleanly: %v", err)
	}
	cases := map[string][]byte{
		"empty":                nil,
		"not a client hello":   {0x02, 0, 0, 0},
		"handshake overruns":   {0x01, 0x00, 0xff, 0xff},
		"truncated mid-hello":  body[:20],
		"no extension block":   body[:47],
		"extension overruns":   patched(body, 45, 0xff, 0xff),
		"ragged extension end": patched(body, 47+2, 0xff, 0xfe),
	}
	for name, b := range cases {
		if _, _, err := walkHelloExtensions(b); !errors.Is(err, ErrNotClientHello) {
			t.Errorf("%s: err = %v, want ErrNotClientHello", name, err)
		}
	}
}

// patched returns a copy of b with the two bytes at off replaced.
func patched(b []byte, off int, hi, lo byte) []byte {
	out := append([]byte(nil), b...)
	out[off], out[off+1] = hi, lo
	return out
}

func TestQuicFakeEmitsDecoysBeforeTheRealDatagram(t *testing.T) {
	payload, meta := quicFixture()
	p := mustBuild(t, "quicfake:count=3,ttl=2", payload, meta)

	if p.WriteCount() != 4 {
		t.Fatalf("WriteCount = %d, want 3 decoys plus the real datagram", p.WriteCount())
	}
	real0, ok := tlsmsg.ParseQUICInitial(payload)
	if !ok {
		t.Fatal("fixture is not a QUIC Initial")
	}
	for i, s := range p.Segments[:3] {
		if s.Kind != strategy.SegFakeRaw || s.TTL != 2 {
			t.Fatalf("decoy %d: kind %s ttl %d", i, s.Kind, s.TTL)
		}
		q, ok := tlsmsg.ParseQUICInitial(s.Data)
		if !ok {
			t.Fatalf("decoy %d is not a parseable QUIC Initial", i)
		}
		if !bytes.Equal(q.DCID(s.Data), real0.DCID(payload)) {
			t.Errorf("decoy %d does not carry the real DCID", i)
		}
		if len(s.Data) != len(payload) {
			t.Errorf("decoy %d is %d bytes, want the real datagram's %d", i, len(s.Data), len(payload))
		}
		if bytes.Equal(s.Data, payload) {
			t.Errorf("decoy %d is byte-identical to the real datagram", i)
		}
	}
	if p.Segments[3].Kind != strategy.SegStream || !bytes.Equal(p.Segments[3].Data, payload) {
		t.Error("the real datagram must be emitted last and unmodified")
	}
	// The decoys are not stream bytes, so they cannot corrupt what the peer
	// reassembles. mustBuild asserts that; this states why it matters here.
	if !bytes.Equal(p.StreamBytes(), payload) {
		t.Error("decoys leaked into the stream")
	}
}

func TestQuicFakeNeedsAQUICInitial(t *testing.T) {
	payload, meta := ttHello(t)
	if _, err := buildSpec(t, "quicfake:count=2", payload, meta); !errors.Is(err, ErrNeedQUIC) {
		t.Fatalf("err = %v, want ErrNeedQUIC", err)
	}
	if _, err := NewRegistry().Get("quicfake:count=99"); !errors.Is(err, strategy.ErrBadValue) {
		t.Error("an out-of-range count must be refused at parse time")
	}
}

// TestUnreachableOpsAreRejectedWithACitation: an honest error beats a missing
// feature. A user pasting a zapret strategy string must learn which mechanism
// is impossible here and why, not "unknown op".
func TestUnreachableOpsAreRejectedWithACitation(t *testing.T) {
	r := NewRegistry()
	want := map[string]string{
		"fake":          "tcp_connection_info",
		"seqovl":        "tcp_connection_info",
		"fakedsplit":    "tcp_connection_info",
		"hostfakesplit": "tcp_connection_info",
		"wssize":        "SO_RCVBUF",
		"mss":           "TCP_MAXSEG",
		"dropsack":      "BPF",
	}
	for name, cite := range want {
		_, err := r.Get(name + ":pos=1")
		if !errors.Is(err, strategy.ErrOpRejected) {
			t.Errorf("%s: err = %v, want ErrOpRejected", name, err)
			continue
		}
		if !strings.Contains(err.Error(), cite) {
			t.Errorf("%s: refusal does not cite %s: %v", name, cite, err)
		}
	}
	// Registered, not absent: the name is known, which is what makes the error
	// specific rather than "unknown op".
	names := strings.Join(r.Names(), ",")
	for name := range want {
		if !strings.Contains(names, name) {
			t.Errorf("%s is not registered", name)
		}
	}
}

// TestLaddersCompile is the load-time proof that the shipped ladder data and the
// shipped op set agree. A ladder naming an op this build does not register must
// fail here, not on the day a user needs the rung.
func TestLaddersCompile(t *testing.T) {
	r := NewRegistry()
	for _, name := range strategy.LadderNames() {
		rungs, err := r.Ladder(name)
		if err != nil {
			t.Fatalf("ladder %q: %v", name, err)
		}
		if len(rungs) == 0 {
			t.Fatalf("ladder %q is empty", name)
		}
		if !rungs[0].IsPlain() {
			t.Errorf("ladder %q rung 1 is %q, want plain (MEASUREMENTS.md §5.2)", name, rungs[0].Label())
		}
		// A spec is a wire format: the prober serialises it, the verdict store
		// caches it, `dpb apply` imports one a stranger pasted. Round-tripping
		// every shipped rung through the real op set is what proves the ops'
		// declared defaults keep canonicalisation idempotent.
		for i, s := range rungs {
			again, err := r.Get(s.String())
			if err != nil {
				t.Fatalf("ladder %q rung %d (%q) does not re-parse: %v", name, i+1, s.String(), err)
			}
			if again.String() != s.String() {
				t.Errorf("ladder %q rung %d: %q canonicalises to %q", name, i+1, s.String(), again.String())
			}
		}
	}
}

// TestTRLadderIsMEASUREMENTS53 pins the shipped ladder to the measurement it
// was lifted from. The order is not a preference: §5.1 measured every rung on
// two axes and §5.3 states the resulting order.
func TestTRLadderIsMEASUREMENTS53(t *testing.T) {
	rungs, err := NewRegistry().Ladder("tr")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", "tlsfrag:pos=snimid", "chunk:size=12", "chunk:size=4", "oob:pos=1"}
	if len(rungs) != len(want) {
		t.Fatalf("%d rungs, want %d", len(rungs), len(want))
	}
	for i, w := range want {
		if got := rungs[i].String(); got != w {
			t.Errorf("rung %d = %q, want %q", i+1, got, w)
		}
	}
	// disorder measured 0/10 (§3.5) and split 0/5 (§3.1) on this line; both are
	// registered and both must stay off the TR ladder.
	joined := strings.Join(want, "|")
	for _, absent := range []string{"disorder", "split"} {
		if strings.Contains(joined, absent) {
			t.Errorf("%s must not be on the TR ladder", absent)
		}
	}
}

// TestEveryRungBuildsAgainstEveryFixture is the universal invariant sweep: for
// every rung of every shipped ladder and every canned first message, either the
// plan is refused with a typed error, or it validates, stays inside the budget
// and reproduces the payload byte for byte.
func TestEveryRungBuildsAgainstEveryFixture(t *testing.T) {
	tls, tm := ttHello(t)
	http, hm := httpFixture("discord.com")
	quic, qm := quicFixture()
	nosni := helloAt(t, "x.example", 60, 400)
	nm := tlsmsg.Parse(nosni, 443)
	nm.SNIStart, nm.SNIEnd, nm.ServerName = -1, -1, ""

	fixtures := []struct {
		name    string
		payload []byte
		meta    tlsmsg.Meta
	}{
		{"tls", tls, tm},
		{"http", http, hm},
		{"quic", quic, qm},
		{"nosni", nosni, nm},
	}
	r := NewRegistry()
	bud := strategy.DefaultBudget()
	for _, ladder := range strategy.LadderNames() {
		rungs, err := r.Ladder(ladder)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range rungs {
			for _, f := range fixtures {
				p, err := s.Build(f.payload, f.meta, allCaps, bud)
				if err != nil {
					if isTypedRefusal(err) {
						continue
					}
					t.Errorf("%s on %s: untyped failure %v", s.Label(), f.name, err)
					continue
				}
				if err := p.Validate(bud); err != nil {
					t.Errorf("%s on %s: plan does not validate: %v", s.Label(), f.name, err)
				}
				if !bytes.Equal(p.StreamBytes(), p.Payload) {
					t.Errorf("%s on %s: stream bytes != payload", s.Label(), f.name)
				}
				if p.WriteCount() > bud.MaxSegments {
					t.Errorf("%s on %s: %d writes", s.Label(), f.name, p.WriteCount())
				}
			}
		}
	}
}

func isTypedRefusal(err error) bool {
	for _, sentinel := range []error{
		strategy.ErrCutAfterSNI, strategy.ErrNeedComplete, strategy.ErrNeedSNI, strategy.ErrNeedHost,
		strategy.ErrCapUnavailable, strategy.ErrBudget, strategy.ErrBadValue, strategy.ErrOpRejected,
		ErrNeedQUIC, ErrNotClientHello, ErrAlreadyPadded, ErrNotApplicable,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// TestRegistrationIsWellFormed leans on strategy.Registry.Register, which
// panics when an OpDoc disagrees with the interface methods or declares a
// non-canonical default. Registering the whole set is therefore a contract test.
func TestRegistrationIsWellFormed(t *testing.T) {
	r := NewRegistry()
	docs := r.Docs()
	if len(docs) != len(All()) {
		t.Fatalf("%d docs for %d ops", len(docs), len(All()))
	}
	for _, d := range docs {
		switch {
		case d.Summary == "":
			t.Errorf("%s has no summary", d.Name)
		case d.Rejected == "" && d.Source == "":
			t.Errorf("%s cites no source", d.Name)
		case d.Risk < 0 || d.Risk > 100:
			t.Errorf("%s has risk %d", d.Name, d.Risk)
		}
		for _, p := range d.Params {
			if p.Doc == "" {
				t.Errorf("%s parameter %s is undocumented", d.Name, p.Name)
			}
		}
	}
	// Install is idempotent and populates the registry package-level Parse
	// consults, which is what makes a user-supplied spec parseable at all.
	if a, b := Install(), Install(); a != b {
		t.Fatal("Install returned two different registries")
	}
	if _, err := strategy.Parse("tlsfrag:pos=snimid"); err != nil {
		t.Fatalf("after Install, the default registry must parse the primary emitter: %v", err)
	}
}

func TestSchedulingOpsRejectBadParameters(t *testing.T) {
	r := NewRegistry()
	for _, spec := range []string{
		"oob:pos=1,junk=999", "oob:pos=1,junk=x", "disorder:pos=1,ttl=0", "disorder:pos=1,ttl=256",
		"chunk:size=0", "quicfake:ttl=0", "tlspad:to=0", "hostpad:len=99999",
	} {
		if _, err := r.Get(spec); !errors.Is(err, strategy.ErrBadValue) {
			t.Errorf("%s: err = %v, want ErrBadValue", spec, err)
		}
	}
	http, hm := httpFixture("discord.com")
	for _, spec := range []string{"oob:pos=snimid", "disorder:pos=snimid"} {
		if _, err := buildSpec(t, spec, http, hm); !errors.Is(err, strategy.ErrNeedSNI) {
			t.Errorf("%s on a plaintext request: err = %v, want ErrNeedSNI", spec, err)
		}
	}
}

// TestStrictModeRefusesADowngrade: the prober must never score a strategy it
// did not actually emit. A split offset that falls outside the payload is
// quietly dropped in normal operation and is an error under Strict.
func TestStrictModeRefusesADowngrade(t *testing.T) {
	payload, meta := ttHello(t)
	for _, spec := range []string{"oob:pos=99999", "split:pos=99999", "disorder:pos=99999", "chunk:size=1"} {
		s, err := NewRegistry().Get(spec)
		if err != nil {
			t.Fatal(err)
		}
		b := &strategy.Builder{
			Payload: append([]byte(nil), payload...),
			Meta:    meta,
			Caps:    allCaps,
			Budget:  strategy.Budget{MaxSegments: 3, MinSegment: 1, MaxPayload: 1 << 16},
			Strict:  true,
		}
		_, err = s.BuildWith(b)
		switch spec {
		case "chunk:size=1":
			// Not a downgrade: chunking the head is what this op does, and the
			// geometry is deterministic given (size, budget).
			if err != nil {
				t.Errorf("%s under a 3-segment budget: %v", spec, err)
			}
		default:
			if !errors.Is(err, strategy.ErrDowngrade) {
				t.Errorf("%s: err = %v, want ErrDowngrade", spec, err)
			}
		}
	}
}

func TestChunkHonoursACustomBudget(t *testing.T) {
	payload, meta := ttHello(t)
	s, err := NewRegistry().Get("chunk:size=4")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Build(payload, meta, allCaps, strategy.Budget{MaxSegments: 6, MinSegment: 1, MaxPayload: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	if p.WriteCount() != 6 {
		t.Fatalf("WriteCount = %d, want the custom budget's 6", p.WriteCount())
	}
	if _, err := s.Build(payload, meta, allCaps, strategy.Budget{MaxSegments: 1, MinSegment: 1, MaxPayload: 1 << 16}); !errors.Is(err, strategy.ErrBudget) {
		t.Error("a one-segment budget cannot express a chunked write and must say so")
	}

	// A builder carrying no budget at all falls back to the shipped default,
	// the same way strategy.Builder does internally — an op must never read a
	// zero budget as "unlimited".
	p, err = s.BuildWith(&strategy.Builder{Payload: append([]byte(nil), payload...), Meta: meta, Caps: allCaps})
	if err != nil {
		t.Fatal(err)
	}
	if p.WriteCount() != strategy.DefaultBudget().MaxSegments {
		t.Errorf("zero budget: %d writes, want the default %d", p.WriteCount(), strategy.DefaultBudget().MaxSegments)
	}
}

// TestRejectedOpsCannotEmitEvenOffTheRegistryPath: Registry.Get refuses them
// first, so this is the backstop for a caller that compiles an op directly.
func TestRejectedOpsCannotEmitEvenOffTheRegistryPath(t *testing.T) {
	n := 0
	for _, o := range All() {
		if o.Doc().Rejected == "" {
			continue
		}
		n++
		step, err := o.Compile(strategy.Args{})
		if err != nil {
			t.Fatalf("%s: Compile: %v", o.Name(), err)
		}
		if err := step.Apply(&strategy.Builder{}); !errors.Is(err, strategy.ErrOpRejected) {
			t.Errorf("%s: Apply err = %v, want ErrOpRejected", o.Name(), err)
		}
	}
	if n != 7 {
		t.Errorf("%d rejected ops registered, want 7", n)
	}
}

func TestPadHelloRefusesUnusableInput(t *testing.T) {
	payload, meta := ttHello(t)

	incomplete := meta
	incomplete.Complete = false
	if _, err := padHello(payload, incomplete, 600); !errors.Is(err, strategy.ErrNeedComplete) {
		t.Errorf("incomplete: err = %v, want ErrNeedComplete", err)
	}
	badOff := meta
	badOff.BodyOff = 0
	if _, err := padHello(payload, badOff, 600); !errors.Is(err, strategy.ErrNeedComplete) {
		t.Errorf("bad body offset: err = %v, want ErrNeedComplete", err)
	}
	noSNI := meta
	noSNI.SNIStart, noSNI.SNIEnd = -1, -1
	if _, err := padHello(payload, noSNI, 600); !errors.Is(err, strategy.ErrNeedSNI) {
		t.Errorf("no sni: err = %v, want ErrNeedSNI", err)
	}

	// A record whose body is not a walkable ClientHello, described by a Meta
	// that claims it is: the rewrite must refuse rather than patch lengths it
	// does not understand.
	junk := append([]byte{0x16, 0x03, 0x01, 0x01, 0x00}, bytes.Repeat([]byte{0xaa}, 256)...)
	jm := meta
	jm.BodyOff, jm.BodyLen, jm.SNIStart, jm.SNIEnd = 5, 256, 100, 110
	if _, err := padHello(junk, jm, 600); !errors.Is(err, ErrNotClientHello) {
		t.Errorf("junk body: err = %v, want ErrNotClientHello", err)
	}
	// A hello with no server_name extension at all, but a Meta that claims one.
	nosni := helloAt(t, "a.example", 60, 300)
	stripped := stripSNIExtension(t, nosni)
	sm := tlsmsg.Parse(stripped, 443)
	sm.SNIStart, sm.SNIEnd, sm.Complete = 60, 69, true
	if _, err := padHello(stripped, sm, 600); !errors.Is(err, ErrNotClientHello) {
		t.Errorf("no server_name extension: err = %v, want ErrNotClientHello", err)
	}
}

// stripSNIExtension rewrites the fixture's server_name extension type to an
// unassigned one, leaving every length untouched.
func stripSNIExtension(tb testing.TB, rec []byte) []byte {
	tb.Helper()
	out := append([]byte(nil), rec...)
	_, exts, err := walkHelloExtensions(out[5:])
	if err != nil {
		tb.Fatal(err)
	}
	for _, e := range exts {
		if e.typ == extServerName {
			binary.BigEndian.PutUint16(out[5+e.off:], fillerExt)
			return out
		}
	}
	tb.Fatal("fixture has no server_name extension")
	return nil
}

func TestAddLengthsRefuseOverflow(t *testing.T) {
	b16 := []byte{0xff, 0xf0}
	if err := addUint16(b16, 64, 0xffff); !errors.Is(err, strategy.ErrBadValue) {
		t.Errorf("uint16 overflow: err = %v", err)
	}
	b24 := []byte{0xff, 0xff, 0xf0}
	if err := addUint24(b24, 64); !errors.Is(err, strategy.ErrBadValue) {
		t.Errorf("uint24 overflow: err = %v", err)
	}
}

func TestDeterminismSeparatesRuleFromConstant(t *testing.T) {
	r := NewRegistry()
	want := map[string]strategy.Determinism{
		"tlsfrag":  strategy.DetRuleBased,
		"tlsevery": strategy.DetRuleBased,
		"chunk":    strategy.DetEmpirical,
		"oob":      strategy.DetEmpirical,
	}
	for _, d := range r.Docs() {
		if w, ok := want[d.Name]; ok && d.Determinism != w {
			t.Errorf("%s: determinism %s, want %s", d.Name, d.Determinism, w)
		}
	}
	// One empirical constant in a pipeline makes the whole result empirical.
	s, err := r.Get("tlsfrag:pos=snimid|chunk:size=12")
	if err != nil {
		t.Fatal(err)
	}
	if s.Determinism() != strategy.DetEmpirical {
		t.Error("a composite with chunk must not claim to be rule-based")
	}
}
