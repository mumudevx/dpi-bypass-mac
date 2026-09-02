package tlsmsg

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// mkQUIC builds a long-header packet with the given version and long-packet-type
// bits: an 8-byte DCID, a 4-byte SCID, an empty token and a 32-byte payload.
func mkQUIC(version uint32, longType byte) []byte {
	payload := bytes.Repeat([]byte{0xab}, 32)

	b := []byte{0xc0 | longType<<4}
	b = binary.BigEndian.AppendUint32(b, version)
	b = append(b, 8)
	b = append(b, bytes.Repeat([]byte{0x11}, 8)...)
	b = append(b, 4)
	b = append(b, bytes.Repeat([]byte{0x22}, 4)...)
	b = append(b, 0x00)                     // token length: 1-byte varint, 0
	b = append(b, 0x40, byte(len(payload))) // length: 2-byte varint
	return append(b, payload...)
}

func TestParseQUICInitial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint32
		typ     byte
	}{
		{"v1", QUICVersion1, 0},
		{"v2", QUICVersion2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := mkQUIC(tc.version, tc.typ)
			q, ok := ParseQUICInitial(b)
			if !ok {
				t.Fatal("not recognised as an Initial")
			}
			if q.Version != tc.version {
				t.Errorf("Version = %#x", q.Version)
			}
			if got := q.DCID(b); !bytes.Equal(got, bytes.Repeat([]byte{0x11}, 8)) {
				t.Errorf("DCID = % x", got)
			}
			if q.SCIDEnd-q.SCIDStart != 4 {
				t.Errorf("SCID length = %d, want 4", q.SCIDEnd-q.SCIDStart)
			}
			if q.TokenStart != q.TokenEnd {
				t.Errorf("token = [%d,%d), want empty", q.TokenStart, q.TokenEnd)
			}
			if q.Length != 32 || q.PayloadOff+q.Length != len(b) {
				t.Errorf("Length = %d, PayloadOff = %d, datagram = %d", q.Length, q.PayloadOff, len(b))
			}

			m := Parse(b, 443)
			if m.Proto != ProtoQUICInitial || !m.Complete {
				t.Errorf("Parse: Proto = %v, Complete = %v", m.Proto, m.Complete)
			}
		})
	}
}

func TestParseQUICInitialRejects(t *testing.T) {
	v1 := mkQUIC(QUICVersion1, 0)

	shortHdr := append([]byte(nil), v1...)
	shortHdr[0] &^= 0x80 // short header

	noFixed := append([]byte(nil), v1...)
	noFixed[0] &^= 0x40 // fixed bit clear: a greased or corrupt packet

	handshake := append([]byte(nil), v1...)
	handshake[0] |= 0x20 // v1 long type 2 (0-RTT), not an Initial

	v2Initial0 := mkQUIC(QUICVersion2, 0) // v1's Initial numbering under v2 is Retry

	unknownVer := append([]byte(nil), v1...)
	binary.BigEndian.PutUint32(unknownVer[1:5], 0xdeadbeef)

	versionNeg := append([]byte(nil), v1...)
	binary.BigEndian.PutUint32(versionNeg[1:5], 0)

	longDCID := append([]byte(nil), v1...)
	longDCID[5] = 21 // over RFC 9000's 20-byte limit

	cases := map[string][]byte{
		"short header":         shortHdr,
		"fixed bit clear":      noFixed,
		"0-RTT not Initial":    handshake,
		"v2 type 0 is Retry":   v2Initial0,
		"unknown version":      unknownVer,
		"version negotiation":  versionNeg,
		"over-long DCID":       longDCID,
		"truncated mid-header": v1[:8],
		"too short":            v1[:3],
		"length past datagram": v1[:len(v1)-1],
		"empty":                nil,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := ParseQUICInitial(in); ok {
				t.Fatal("accepted")
			}
			if got := Classify(in, 443); got == ProtoQUICInitial {
				t.Fatal("Classify called it a QUIC Initial")
			}
		})
	}
}

func TestQUICVarint(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		n    int
		ok   bool
	}{
		{[]byte{0x00}, 0, 1, true},
		{[]byte{0x25}, 37, 1, true},
		{[]byte{0x7b, 0xbd}, 15293, 2, true},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4, true},
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8, true},
		{[]byte{0x40}, 0, 0, false}, // declares 2 bytes, only 1 present
		{nil, 0, 0, false},
	}
	for _, c := range cases {
		v, n, ok := quicVarint(c.in, 0)
		if v != c.want || n != c.n || ok != c.ok {
			t.Errorf("quicVarint(% x) = (%d,%d,%v), want (%d,%d,%v)", c.in, v, n, ok, c.want, c.n, c.ok)
		}
	}
	if _, _, ok := quicVarint([]byte{0x00}, -1); ok {
		t.Error("negative offset accepted")
	}
}
