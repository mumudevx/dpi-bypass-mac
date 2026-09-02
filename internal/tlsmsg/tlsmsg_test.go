package tlsmsg

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// The captured post-quantum ClientHello reproduces the exact hello the ruleprobe
// run in MEASUREMENTS.md §3.2 measured against: body=1497 with the SNI at
// [112,122). Every cut position in that table is stated relative to these two
// numbers, so if this test fails the measured rule no longer describes the bytes
// the tool actually emits.
const (
	pqTotal     = 1502
	pqBodyLen   = 1497
	pqSNIStart  = 112
	pqSNIEnd    = 122
	pqServerNam = "discord.gg"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return b
}

func TestParsePostQuantumClientHello(t *testing.T) {
	b := load(t, "pq_1601.bin")
	if len(b) != pqTotal {
		t.Fatalf("capture is %d bytes, want %d", len(b), pqTotal)
	}
	m := Parse(b, 443)

	if m.Proto != ProtoTLS {
		t.Errorf("Proto = %v, want tls", m.Proto)
	}
	if !m.Complete {
		t.Error("Complete = false, want true")
	}
	if m.Truncated {
		t.Error("Truncated = true; only the reader may set it")
	}
	if m.BodyOff != 5 || m.BodyLen != pqBodyLen {
		t.Errorf("body = [%d,+%d), want [5,+%d)", m.BodyOff, m.BodyLen, pqBodyLen)
	}
	if m.SNIStart != pqSNIStart || m.SNIEnd != pqSNIEnd {
		t.Errorf("sni = [%d,%d), want [%d,%d)", m.SNIStart, m.SNIEnd, pqSNIStart, pqSNIEnd)
	}
	if m.ServerName != pqServerNam {
		t.Errorf("ServerName = %q, want %q", m.ServerName, pqServerNam)
	}
	if m.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", m.DstPort)
	}
	if got := string(b[m.BodyOff+m.SNIStart : m.BodyOff+m.SNIEnd]); got != pqServerNam {
		t.Errorf("body-relative offsets address %q, want %q", got, pqServerNam)
	}
	if m.HostStart != -1 || m.HostEnd != -1 || m.HeaderEnd != -1 {
		t.Errorf("HTTP offsets set on a TLS hello: %+v", m)
	}
	if m.RecordEnd() != pqTotal {
		t.Errorf("RecordEnd = %d, want %d", m.RecordEnd(), pqTotal)
	}
	if [5]byte(b[:5]) != m.RecHdr {
		t.Errorf("RecHdr = % x, want % x", m.RecHdr, b[:5])
	}
}

// TestMaxFirstRecordEndReproducesMeasuredRule drives every cut position in
// MEASUREMENTS.md §3.2 through the predicate and asserts it reproduces the
// measured pass/fail column. Fourteen data points, one rule. This cannot break
// because the network changed, only because the code regressed.
func TestMaxFirstRecordEndReproducesMeasuredRule(t *testing.T) {
	m := Parse(load(t, "pq_1601.bin"), 443)
	max, ok := m.MaxFirstRecordEnd()
	if !ok {
		t.Fatal("MaxFirstRecordEnd not ok on a hello with an SNI")
	}
	if max != pqSNIEnd-1 {
		t.Fatalf("MaxFirstRecordEnd = %d, want %d", max, pqSNIEnd-1)
	}

	cases := []struct {
		name    string
		recEnd  int
		through bool
	}{
		// §3.2, 66 shuffled trials, both records in one TCP segment.
		{"sniStart-20", pqSNIStart - 20, true},
		{"sniStart-1", pqSNIStart - 1, true},
		{"sniStart", pqSNIStart, true},
		{"sniStart+1", pqSNIStart + 1, true},
		{"sniMid", (pqSNIStart + pqSNIEnd) / 2, true},
		{"sniEnd-1", pqSNIEnd - 1, true},
		{"sniEnd", pqSNIEnd, false},
		{"sniEnd+1", pqSNIEnd + 1, false},
		{"sniEnd+20", pqSNIEnd + 20, false},
		{"sniEnd+200", pqSNIEnd + 200, false},
		// §3, periodic reframing: the same predicate explains these too.
		{"tlsrec-every-16", 16, true},
		{"tlsrec-every-64", 64, true},
		{"tlsrec-every-256", 256, false},
		// The unfragmented baseline: the record ends past the hostname, 0/3.
		{"none", pqBodyLen, false},
	}
	for _, c := range cases {
		if got := c.recEnd <= max; got != c.through {
			t.Errorf("%s: firstRecordEnd=%d <= %d is %v, measured %v",
				c.name, c.recEnd, max, got, c.through)
		}
	}
}

func TestMaxFirstRecordEndWithoutSNI(t *testing.T) {
	m := Parse(load(t, "nosni.bin"), 443)
	if m.Proto != ProtoTLS || !m.Complete {
		t.Fatalf("nosni capture did not parse as a complete TLS hello: %+v", m)
	}
	if m.HasSNI() {
		t.Fatalf("HasSNI on a hello with no server_name extension: [%d,%d)", m.SNIStart, m.SNIEnd)
	}
	if m.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", m.ServerName)
	}
	if _, ok := m.MaxFirstRecordEnd(); ok {
		t.Error("MaxFirstRecordEnd ok without an SNI; a reframer must refuse, not guess")
	}
}

func TestParseClassicHello(t *testing.T) {
	b := load(t, "classic.bin")
	m := Parse(b, 443)
	if m.Proto != ProtoTLS || !m.Complete {
		t.Fatalf("classic capture: %+v", m)
	}
	if m.ServerName != "cloudflare.com" {
		t.Errorf("ServerName = %q", m.ServerName)
	}
	if got := string(b[m.BodyOff+m.SNIStart : m.BodyOff+m.SNIEnd]); got != "cloudflare.com" {
		t.Errorf("offsets address %q", got)
	}
	if m.BodyLen != len(b)-5 {
		t.Errorf("BodyLen = %d, want %d", m.BodyLen, len(b)-5)
	}
}

// TestCompleteFlipsAtRecordBoundary feeds the capture one byte at a time. The
// flag must flip at exactly 5+recLen and never before: planning a record split
// against a prefix is how the previous implementation degraded tlsfrag into a
// one-byte TCP split, which measures 0/5 (MEASUREMENTS.md §3, §3.5).
func TestCompleteFlipsAtRecordBoundary(t *testing.T) {
	b := load(t, "pq_1601.bin")
	for n := 1; n <= len(b); n++ {
		m := Parse(b[:n], 443)
		want := n >= pqTotal
		if m.Complete != want {
			t.Fatalf("n=%d: Complete=%v, want %v", n, m.Complete, want)
		}
		if n >= 5 && m.BodyLen != pqBodyLen {
			t.Fatalf("n=%d: BodyLen=%d, want %d", n, m.BodyLen, pqBodyLen)
		}
		// Whatever it reports must be readable: no offset may point past what
		// was actually buffered.
		if m.HasSNI() && m.BodyOff+m.SNIEnd > n {
			t.Fatalf("n=%d: sniEnd %d reaches past the buffer", n, m.BodyOff+m.SNIEnd)
		}
		want2, ok := Need(b[:n], ProtoTLS)
		if !ok {
			t.Fatalf("n=%d: Need not ok on a TLS prefix", n)
		}
		switch {
		case n < 5 && want2 != 5-n:
			t.Fatalf("n=%d: Need=%d, want %d", n, want2, 5-n)
		case n >= 5 && n < pqTotal && want2 != pqTotal-n:
			t.Fatalf("n=%d: Need=%d, want %d", n, want2, pqTotal-n)
		case n >= pqTotal && want2 != 0:
			t.Fatalf("n=%d: Need=%d, want 0", n, want2)
		}
	}
}

// TestSNIFoundInPrefix pins that a hostname buffered before the record completes
// is still located, so a flow can be named and scoped without waiting.
func TestSNIFoundInPrefix(t *testing.T) {
	b := load(t, "pq_1601.bin")
	m := Parse(b[:5+pqSNIEnd], 443)
	if m.Complete {
		t.Fatal("Complete on a prefix")
	}
	if m.ServerName != pqServerNam {
		t.Errorf("ServerName = %q, want %q", m.ServerName, pqServerNam)
	}
	// One byte short of the full hostname the SNI must not be reported at all,
	// because a partial hostname would scope the flow to the wrong name.
	if m2 := Parse(b[:5+pqSNIEnd-1], 443); m2.HasSNI() {
		t.Errorf("SNI reported from a truncated hostname: %q", m2.ServerName)
	}
}

type ext struct {
	typ  uint16
	data []byte
}

// mkHello builds a minimal but structurally valid ClientHello record.
func mkHello(sni string, pre ...ext) []byte {
	var exts []byte
	appendExt := func(typ uint16, data []byte) {
		exts = binary.BigEndian.AppendUint16(exts, typ)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(data)))
		exts = append(exts, data...)
	}
	for _, e := range pre {
		appendExt(e.typ, e.data)
	}
	if sni != "" {
		var sn []byte
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(sni)+3))
		sn = append(sn, sniTypeHostName)
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(sni)))
		sn = append(sn, sni...)
		appendExt(extServerName, sn)
	}

	var body []byte
	body = append(body, 0x03, 0x03)             // legacy_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0)                      // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := []byte{hsTypeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{recTypeHandshake, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestParseSyntheticHellos(t *testing.T) {
	greaseSNI := mkHello("example.com", ext{0x0a0a, nil}, ext{0x1a1a, []byte{1, 2, 3}})

	cases := []struct {
		name string
		in   []byte
		sni  string
	}{
		{"plain", mkHello("example.com"), "example.com"},
		{"grease-tolerant", greaseSNI, "example.com"},
		{"no extensions", mkHello(""), ""},
		{"single-label", mkHello("localhost"), "localhost"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := Parse(c.in, 443)
			if m.Proto != ProtoTLS || !m.Complete {
				t.Fatalf("Proto=%v Complete=%v", m.Proto, m.Complete)
			}
			if m.ServerName != c.sni {
				t.Fatalf("ServerName = %q, want %q", m.ServerName, c.sni)
			}
			if c.sni == "" {
				return
			}
			if got := string(c.in[m.BodyOff+m.SNIStart : m.BodyOff+m.SNIEnd]); got != c.sni {
				t.Fatalf("offsets address %q", got)
			}
		})
	}
}

// TestParseMalformedHellos pins that every truncation and every lying length
// field yields "no SNI" rather than a panic or an offset into thin air.
func TestParseMalformedHellos(t *testing.T) {
	good := mkHello("example.com")

	shortHsLen := append([]byte(nil), good...)
	shortHsLen[6], shortHsLen[7], shortHsLen[8] = 0, 0, 10 // stops inside the random

	// The extension-block length sits right after the compression methods.
	const extLenOff = 5 + 4 + 2 + 32 + 1 + (2 + 2) + (1 + 1)
	shortExtLen := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(shortExtLen[extLenOff:], 4) // cuts the SNI extension off

	emptyName := mkHello("")
	emptyNameEntry := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(emptyNameEntry[len(emptyNameEntry)-len("example.com")-2:], 0)

	notHello := append([]byte(nil), good...)
	notHello[5] = 0x02 // ServerHello

	cases := map[string][]byte{
		"handshake length truncates the body": shortHsLen,
		"extension block cut by its length":   shortExtLen,
		"empty host_name entry":               emptyNameEntry,
		"no server_name extension":            emptyName,
		"not a ClientHello":                   notHello,
		"header only":                         good[:5],
		"one byte":                            good[:1],
		"cut inside the hostname":             good[:len(good)-4],
		"empty":                               {},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			m := Parse(in, 443)
			if m.HasSNI() {
				t.Fatalf("SNI reported: [%d,%d) %q", m.SNIStart, m.SNIEnd, m.ServerName)
			}
		})
	}
}

// TestParseToleratesOverDeclaredLengths pins the deliberate asymmetry: a length
// that declares MORE than is buffered is clamped, because a ClientHello may
// legally span records and because the flow layer wants a name before the
// message completes. A length that declares LESS is a real malformation and is
// rejected (covered by TestParseMalformedHellos).
func TestParseToleratesOverDeclaredLengths(t *testing.T) {
	over := mkHello("example.com")
	over[6], over[7], over[8] = 0x00, 0xff, 0xff // handshake claims to continue

	m := Parse(over, 443)
	if m.ServerName != "example.com" {
		t.Fatalf("ServerName = %q, want example.com", m.ServerName)
	}
	if m.BodyOff+m.SNIEnd > len(over) {
		t.Fatalf("sniEnd %d reaches past the buffer (%d)", m.BodyOff+m.SNIEnd, len(over))
	}
}

// TestParseSNIListEntries covers the server_name list itself: an entry of an
// unknown NameType must be skipped rather than mistaken for the hostname, and a
// list length that overruns its own extension must be refused.
func TestParseSNIListEntries(t *testing.T) {
	entry := func(kind byte, name string) []byte {
		e := []byte{kind}
		e = binary.BigEndian.AppendUint16(e, uint16(len(name)))
		return append(e, name...)
	}
	list := func(entries ...[]byte) []byte {
		var body []byte
		for _, e := range entries {
			body = append(body, e...)
		}
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
	}

	t.Run("unknown entry type is skipped", func(t *testing.T) {
		in := mkHello("", ext{extServerName, list(entry(0x02, "skipme"), entry(sniTypeHostName, "example.com"))})
		m := Parse(in, 443)
		if m.ServerName != "example.com" {
			t.Fatalf("ServerName = %q", m.ServerName)
		}
		if got := string(in[m.BodyOff+m.SNIStart : m.BodyOff+m.SNIEnd]); got != "example.com" {
			t.Fatalf("offsets address %q", got)
		}
	})

	t.Run("list length overruns the extension", func(t *testing.T) {
		data := list(entry(sniTypeHostName, "example.com"))
		binary.BigEndian.PutUint16(data, 0xffff)
		if m := Parse(mkHello("", ext{extServerName, data}), 443); m.HasSNI() {
			t.Fatalf("SNI reported: %q", m.ServerName)
		}
	})

	t.Run("entry length overruns the list", func(t *testing.T) {
		data := list(entry(sniTypeHostName, "example.com"))
		binary.BigEndian.PutUint16(data[3:], 0xff) // name claims 255 bytes
		if m := Parse(mkHello("", ext{extServerName, data}), 443); m.HasSNI() {
			t.Fatalf("SNI reported: %q", m.ServerName)
		}
	})

	t.Run("no host_name entry", func(t *testing.T) {
		in := mkHello("", ext{extServerName, list(entry(0x02, "skipme"))})
		if m := Parse(in, 443); m.HasSNI() {
			t.Fatalf("SNI reported: %q", m.ServerName)
		}
	})
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want Proto
	}{
		{"tls hello", mkHello("a.example"), ProtoTLS},
		{"tls first byte only", []byte{0x16}, ProtoTLS},
		{"tls wrong version", []byte{0x16, 0x02, 0x01}, ProtoUnknown},
		{"tls future version", []byte{0x16, 0x03, 0x09}, ProtoUnknown},
		{"tls alert record", []byte{0x15, 0x03, 0x01, 0, 2}, ProtoUnknown},
		{"http get", []byte("GET / HTTP/1.1\r\n\r\n"), ProtoHTTP},
		{"http prefix", []byte("GE"), ProtoHTTP},
		{"http lookalike", []byte("GETX / HTTP/1.1\r\n"), ProtoUnknown},
		{"quic initial", mkQUIC(QUICVersion1, 0), ProtoQUICInitial},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_9.0\r\n"), ProtoUnknown},
		{"empty", nil, ProtoUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.in, 443); got != c.want {
				t.Fatalf("Classify = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseHTTPRequest(t *testing.T) {
	req := []byte("GET /a HTTP/1.1\r\nUser-Agent: x\r\nHost: discord.com:8080\r\n\r\n")
	m := Parse(req, 80)
	if m.Proto != ProtoHTTP {
		t.Fatalf("Proto = %v", m.Proto)
	}
	if !m.Complete {
		t.Error("Complete = false")
	}
	if !m.HasHost() {
		t.Fatal("HasHost = false")
	}
	if got := string(req[m.HostStart:m.HostEnd]); got != "discord.com" {
		t.Errorf("host offsets address %q", got)
	}
	if m.ServerName != "discord.com" {
		t.Errorf("ServerName = %q", m.ServerName)
	}
	if m.HeaderEnd != len(req) {
		t.Errorf("HeaderEnd = %d, want %d", m.HeaderEnd, len(req))
	}
	if m.HasSNI() {
		t.Error("SNI offsets set on an HTTP request")
	}
	if _, ok := m.MaxFirstRecordEnd(); ok {
		t.Error("MaxFirstRecordEnd ok on an HTTP request")
	}
}

func TestParseHTTPIncomplete(t *testing.T) {
	m := Parse([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n"), 80)
	if m.Proto != ProtoHTTP {
		t.Fatalf("Proto = %v", m.Proto)
	}
	if m.Complete {
		t.Error("Complete on an unterminated header block")
	}
	if m.HeaderEnd != -1 {
		t.Errorf("HeaderEnd = %d, want -1", m.HeaderEnd)
	}
	if m.ServerName != "a.example" {
		t.Errorf("ServerName = %q", m.ServerName)
	}
}

func TestParseUnknownIsAllNegativeOne(t *testing.T) {
	m := Parse([]byte{0x00, 0x01, 0x02}, 22)
	if m.Proto != ProtoUnknown {
		t.Fatalf("Proto = %v", m.Proto)
	}
	if m.SNIStart != -1 || m.SNIEnd != -1 || m.HostStart != -1 || m.HostEnd != -1 || m.HeaderEnd != -1 {
		t.Fatalf("offsets not -1: %+v", m)
	}
	if m.HasSNI() || m.HasHost() {
		t.Fatal("HasSNI/HasHost true on an unknown protocol")
	}
}

func TestNeed(t *testing.T) {
	hello := mkHello("a.example")
	cases := []struct {
		name string
		in   []byte
		p    Proto
		want int
		ok   bool
	}{
		{"tls complete", hello, ProtoTLS, 0, true},
		{"tls needs header", hello[:2], ProtoTLS, 3, true},
		{"tls needs body", hello[:10], ProtoTLS, len(hello) - 10, true},
		{"tls wrong shape", []byte("GET /"), ProtoTLS, 0, false},
		{"http complete", []byte("GET / HTTP/1.1\r\n\r\n"), ProtoHTTP, 0, true},
		{"http partial", []byte("GET / HTTP/1.1\r\n"), ProtoHTTP, 1, true},
		{"http prefix", []byte("GE"), ProtoHTTP, 1, true},
		{"http junk", []byte{0xff}, ProtoHTTP, 0, false},
		{"http malformed line", []byte("GET /\r\n"), ProtoHTTP, 0, false},
		{"quic", mkQUIC(QUICVersion1, 0), ProtoQUICInitial, 0, true},
		{"quic junk", []byte{0x00}, ProtoQUICInitial, 0, false},
		{"unknown", []byte{0x00}, ProtoUnknown, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Need(c.in, c.p)
			if got != c.want || ok != c.ok {
				t.Fatalf("Need = (%d,%v), want (%d,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestProtoString(t *testing.T) {
	want := map[Proto]string{
		ProtoUnknown: "unknown", ProtoTLS: "tls", ProtoHTTP: "http",
		ProtoQUICInitial: "quic", Proto(99): "unknown",
	}
	for p, s := range want {
		if got := p.String(); got != s {
			t.Errorf("Proto(%d).String() = %q, want %q", p, got, s)
		}
	}
}

func TestErrNoSNIIsStable(t *testing.T) {
	if ErrNoSNI == nil || ErrNoSNI.Error() == "" {
		t.Fatal("ErrNoSNI must be a usable sentinel for callers that require a name")
	}
}
