package tlsmsg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// records splits a concatenation of TLS records back apart, returning each
// record's header and body. It is how every SplitRecord test checks that the
// output is structurally valid rather than merely the right length.
func records(t *testing.T, b []byte) []struct {
	H    Header
	Body []byte
} {
	t.Helper()
	var out []struct {
		H    Header
		Body []byte
	}
	for len(b) > 0 {
		h, ok := ParseHeader(b)
		if !ok {
			t.Fatalf("trailing %d bytes are not a record header", len(b))
		}
		if len(b) < recHdrLen+h.Length {
			t.Fatalf("record declares %d bytes, %d remain", h.Length, len(b)-recHdrLen)
		}
		out = append(out, struct {
			H    Header
			Body []byte
		}{h, b[recHdrLen : recHdrLen+h.Length]})
		b = b[recHdrLen+h.Length:]
	}
	return out
}

// TestSplitRecordAtSNIMid is the shipped primary emitter's byte-level golden: the
// captured hello cut inside the hostname produces two structurally valid records
// in one buffer, the first ending at 117 which is <= sniEnd-1 = 121
// (MEASUREMENTS.md §3.2).
func TestSplitRecordAtSNIMid(t *testing.T) {
	rec := load(t, "pq_1601.bin")
	m := Parse(rec, 443)
	cut := (m.SNIStart + m.SNIEnd) / 2

	out, err := SplitRecord(rec, []int{cut})
	if err != nil {
		t.Fatalf("SplitRecord: %v", err)
	}
	if len(out) != len(rec)+recHdrLen {
		t.Fatalf("len = %d, want %d", len(out), len(rec)+recHdrLen)
	}

	rs := records(t, out)
	if len(rs) != 2 {
		t.Fatalf("got %d records, want 2", len(rs))
	}
	if rs[0].H.Length != cut {
		t.Errorf("first record body = %d, want %d", rs[0].H.Length, cut)
	}
	if rs[1].H.Length != pqBodyLen-cut {
		t.Errorf("second record body = %d, want %d", rs[1].H.Length, pqBodyLen-cut)
	}
	for i, r := range rs {
		if r.H.Type != recTypeHandshake || r.H.Version != 0x0301 {
			t.Errorf("record %d header = %+v, want the original type/version", i, r.H)
		}
	}

	// The invariant that matters: the record layer changed, the stream did not.
	joined := append(append([]byte(nil), rs[0].Body...), rs[1].Body...)
	if !bytes.Equal(joined, rec[recHdrLen:]) {
		t.Fatal("split changed the body bytes")
	}
	// And the hostname is genuinely straddling the boundary.
	if cut <= m.SNIStart || cut >= m.SNIEnd {
		t.Fatalf("cut %d is not inside the hostname [%d,%d)", cut, m.SNIStart, m.SNIEnd)
	}
}

func TestSplitRecordMultipleCuts(t *testing.T) {
	rec := load(t, "pq_1601.bin")
	cuts := []int{16, 64, 121, 1496}

	out, err := SplitRecord(rec, cuts)
	if err != nil {
		t.Fatalf("SplitRecord: %v", err)
	}
	rs := records(t, out)
	if len(rs) != len(cuts)+1 {
		t.Fatalf("got %d records, want %d", len(rs), len(cuts)+1)
	}

	var joined []byte
	prev := 0
	for i, c := range append(append([]int(nil), cuts...), pqBodyLen) {
		if rs[i].H.Length != c-prev {
			t.Errorf("record %d body = %d, want %d", i, rs[i].H.Length, c-prev)
		}
		joined = append(joined, rs[i].Body...)
		prev = c
	}
	if !bytes.Equal(joined, rec[recHdrLen:]) {
		t.Fatal("split changed the body bytes")
	}
}

func TestSplitRecordNoCutsIsIdentity(t *testing.T) {
	rec := load(t, "classic.bin")
	out, err := SplitRecord(rec, nil)
	if err != nil {
		t.Fatalf("SplitRecord: %v", err)
	}
	if !bytes.Equal(out, rec) {
		t.Fatal("zero cuts must reproduce the record byte for byte")
	}
	if &out[0] == &rec[0] {
		t.Fatal("SplitRecord aliased its input; a Plan must own its bytes")
	}
}

func TestSplitRecordErrors(t *testing.T) {
	rec := load(t, "classic.bin")
	bodyLen := len(rec) - recHdrLen

	cases := []struct {
		name string
		rec  []byte
		cuts []int
		want error
	}{
		{"short header", rec[:4], nil, ErrNotRecord},
		{"truncated body", rec[:len(rec)-1], nil, ErrShortRecord},
		{"trailing bytes", append(append([]byte(nil), rec...), 0x17), nil, ErrTrailingBytes},
		{"cut at zero", rec, []int{0}, ErrCutRange},
		{"negative cut", rec, []int{-1}, ErrCutRange},
		{"cut at body end", rec, []int{bodyLen}, ErrCutRange},
		{"cut past body end", rec, []int{bodyLen + 1}, ErrCutRange},
		{"repeated cut", rec, []int{5, 5}, ErrCutOrder},
		{"descending cuts", rec, []int{20, 5}, ErrCutOrder},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := SplitRecord(c.rec, c.cuts)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if out != nil {
				t.Fatalf("output returned alongside an error: % x", out)
			}
		})
	}
}

func TestParseHeaderRoundTrip(t *testing.T) {
	if _, ok := ParseHeader([]byte{0x16, 0x03}); ok {
		t.Fatal("ParseHeader ok on a 2-byte buffer")
	}
	h, ok := ParseHeader(load(t, "pq_1601.bin"))
	if !ok {
		t.Fatal("ParseHeader not ok on the capture")
	}
	want := Header{Type: recTypeHandshake, Version: 0x0301, Length: pqBodyLen}
	if h != want {
		t.Fatalf("Header = %+v, want %+v", h, want)
	}
	b := h.Bytes()
	if !bytes.Equal(b[:], load(t, "pq_1601.bin")[:recHdrLen]) {
		t.Fatalf("Bytes() = % x", b)
	}
	if binary.BigEndian.Uint16(b[3:]) != pqBodyLen {
		t.Fatal("length field did not round-trip")
	}
}
