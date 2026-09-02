package tlsmsg

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func seedCorpus(f *testing.F) [][]byte {
	f.Helper()
	var out [][]byte
	for _, name := range []string{"pq_1601.bin", "classic.bin", "nosni.bin"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatalf("read testdata: %v", err)
		}
		out = append(out, b)
	}
	out = append(out,
		mkHello("example.com"),
		mkHello(""),
		mkQUIC(QUICVersion1, 0),
		mkQUIC(QUICVersion2, 1),
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("POST /x HTTP/1.0\r\nHost: [::1]:8080\r\nContent-Length: 3\r\n\r\nabc"),
		[]byte{0x16},
		nil,
	)
	return out
}

// FuzzParse asserts the property the whole tool leans on: whatever Parse reports,
// the offsets it reports are inside the buffer it was given. A single
// out-of-range offset here becomes an out-of-range read in the emitter, on a
// payload an adversary partly controls.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus(f) {
		f.Add(s, 443)
	}
	f.Fuzz(func(t *testing.T, b []byte, port int) {
		m := Parse(b, port)

		if m.DstPort != port {
			t.Fatalf("DstPort = %d, want %d", m.DstPort, port)
		}
		if m.Truncated {
			t.Fatal("Parse set Truncated; only the reader may")
		}
		if m.Proto != ProtoTLS && (m.BodyOff != 0 || m.BodyLen != 0) {
			t.Fatalf("non-TLS proto %v carries a record body [%d,+%d)", m.Proto, m.BodyOff, m.BodyLen)
		}

		if m.HasSNI() {
			if m.Proto != ProtoTLS {
				t.Fatalf("SNI reported for proto %v", m.Proto)
			}
			if m.SNIStart < 0 || m.SNIEnd > m.BodyLen {
				t.Fatalf("sni [%d,%d) escapes the declared body (%d)", m.SNIStart, m.SNIEnd, m.BodyLen)
			}
			// The read the emitter will actually perform.
			if got := string(b[m.BodyOff+m.SNIStart : m.BodyOff+m.SNIEnd]); got != m.ServerName {
				t.Fatalf("offsets address %q, ServerName is %q", got, m.ServerName)
			}
			if max, ok := m.MaxFirstRecordEnd(); !ok || max != m.SNIEnd-1 {
				t.Fatalf("MaxFirstRecordEnd = (%d,%v)", max, ok)
			}
		}

		if m.HasHost() {
			if m.Proto != ProtoHTTP {
				t.Fatalf("Host reported for proto %v", m.Proto)
			}
			if m.HostEnd > len(b) {
				t.Fatalf("host [%d,%d) escapes the buffer (%d)", m.HostStart, m.HostEnd, len(b))
			}
			if m.Complete && m.HostEnd > m.HeaderEnd {
				t.Fatalf("host [%d,%d) escapes the header block (ends %d)", m.HostStart, m.HostEnd, m.HeaderEnd)
			}
			_ = string(b[m.HostStart:m.HostEnd])
		}

		if m.Complete && m.Proto == ProtoTLS && m.RecordEnd() > len(b) {
			t.Fatalf("Complete with a record end of %d past a %d-byte buffer", m.RecordEnd(), len(b))
		}

		// Need must agree with Complete, or the reader loops forever or stops
		// early on the same bytes.
		if want, ok := Need(b, m.Proto); ok && m.Proto != ProtoUnknown {
			if (want == 0) != m.Complete {
				t.Fatalf("Need=%d but Complete=%v", want, m.Complete)
			}
		}
	})
}

// FuzzSplitRecord asserts the invariant that makes a reframing emitter safe to
// ship: the record layer may change, the stream may not. If this ever fails, the
// tool can corrupt a connection it was meant to rescue.
func FuzzSplitRecord(f *testing.F) {
	for _, s := range seedCorpus(f) {
		f.Add(s, 1, 0, 0)
	}
	f.Fuzz(func(t *testing.T, rec []byte, c1, c2, c3 int) {
		cuts := make([]int, 0, 3)
		for _, c := range []int{c1, c2, c3} {
			if c != 0 {
				cuts = append(cuts, c)
			}
		}
		out, err := SplitRecord(rec, cuts)
		if err != nil {
			if out != nil {
				t.Fatal("output returned alongside an error")
			}
			return
		}

		h, ok := ParseHeader(rec)
		if !ok {
			t.Fatal("SplitRecord accepted a buffer with no header")
		}
		body := rec[recHdrLen:]

		var joined []byte
		rest := out
		n := 0
		for len(rest) > 0 {
			rh, ok := ParseHeader(rest)
			if !ok {
				t.Fatalf("output tail of %d bytes is not a record", len(rest))
			}
			if rh.Type != h.Type || rh.Version != h.Version {
				t.Fatalf("record %d changed type/version: %+v", n, rh)
			}
			if rh.Length == 0 {
				t.Fatalf("record %d is empty", n)
			}
			if len(rest) < recHdrLen+rh.Length {
				t.Fatalf("record %d declares %d bytes, %d remain", n, rh.Length, len(rest)-recHdrLen)
			}
			joined = append(joined, rest[recHdrLen:recHdrLen+rh.Length]...)
			rest = rest[recHdrLen+rh.Length:]
			n++
		}
		if n != len(cuts)+1 {
			t.Fatalf("got %d records, want %d", n, len(cuts)+1)
		}
		if !bytes.Equal(joined, body) {
			t.Fatal("split changed the body bytes")
		}
	})
}

// FuzzParseQUICInitial pins that the long-header walk never reads past the
// datagram and never reports an extent it cannot address.
func FuzzParseQUICInitial(f *testing.F) {
	for _, s := range seedCorpus(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		q, ok := ParseQUICInitial(b)
		if !ok {
			return
		}
		for _, e := range [][2]int{
			{q.DCIDStart, q.DCIDEnd}, {q.SCIDStart, q.SCIDEnd}, {q.TokenStart, q.TokenEnd},
		} {
			if e[0] < 0 || e[1] < e[0] || e[1] > len(b) {
				t.Fatalf("extent [%d,%d) escapes a %d-byte datagram", e[0], e[1], len(b))
			}
		}
		if q.PayloadOff+q.Length > len(b) {
			t.Fatalf("payload [%d,+%d) escapes a %d-byte datagram", q.PayloadOff, q.Length, len(b))
		}
		_ = q.DCID(b)
	})
}
