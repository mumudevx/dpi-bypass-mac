package tlsmsg

import "encoding/binary"

// QUIC versions we recognise. Anything else — including version-negotiation
// packets, whose version field is zero — is not treated as an Initial, so an
// unknown future version is relayed verbatim rather than mangled.
const (
	QUICVersion1 uint32 = 0x00000001 // RFC 9000
	QUICVersion2 uint32 = 0x6b3343cf // RFC 9369
)

// maxCIDLen is RFC 9000 §17.2: a connection ID is at most 20 bytes in v1.
const maxCIDLen = 20

// QUICInitial describes a QUIC long-header Initial packet. Every field is a
// read-only extent into the datagram: this package never decrypts, because the
// Initial keys are derived from the DCID and the payload of a real client Initial
// is 1200+ bytes of AEAD we have no reason to touch. The extents exist so
// quicfake can craft a decoy carrying the SAME DCID.
type QUICInitial struct {
	Version    uint32
	DCIDStart  int
	DCIDEnd    int
	SCIDStart  int
	SCIDEnd    int
	TokenStart int
	TokenEnd   int
	Length     int // declared length of packet number + protected payload
	PayloadOff int // offset of the packet number field
}

// DCID returns the destination connection ID.
func (q QUICInitial) DCID(b []byte) []byte { return b[q.DCIDStart:q.DCIDEnd] }

// ParseQUICInitial reports whether b is a QUIC v1 or v2 long-header Initial and,
// if so, where its variable-length fields sit.
func ParseQUICInitial(b []byte) (QUICInitial, bool) {
	var q QUICInitial
	// Long header form (0x80) with the fixed bit set (0x40). A short-header or
	// greased packet fails here.
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return q, false
	}
	q.Version = binary.BigEndian.Uint32(b[1:5])
	switch q.Version {
	case QUICVersion1:
		if (b[0]>>4)&0x03 != 0 { // v1: Initial is long packet type 0
			return q, false
		}
	case QUICVersion2:
		if (b[0]>>4)&0x03 != 1 { // v2 renumbered: Initial is type 1
			return q, false
		}
	default:
		return q, false
	}

	p := 5
	dl := int(b[p])
	p++
	if dl > maxCIDLen || p+dl > len(b) {
		return q, false
	}
	q.DCIDStart, q.DCIDEnd = p, p+dl
	p += dl

	if p >= len(b) {
		return q, false
	}
	sl := int(b[p])
	p++
	if sl > maxCIDLen || p+sl > len(b) {
		return q, false
	}
	q.SCIDStart, q.SCIDEnd = p, p+sl
	p += sl

	tokLen, n, ok := quicVarint(b, p)
	if !ok {
		return q, false
	}
	p += n
	if tokLen > uint64(len(b)-p) {
		return q, false
	}
	q.TokenStart, q.TokenEnd = p, p+int(tokLen)
	p += int(tokLen)

	length, n, ok := quicVarint(b, p)
	if !ok {
		return q, false
	}
	p += n
	if length > uint64(len(b)-p) {
		return q, false
	}
	q.Length = int(length)
	q.PayloadOff = p
	return q, true
}

func isQUICInitial(b []byte) bool {
	_, ok := ParseQUICInitial(b)
	return ok
}

// quicVarint decodes an RFC 9000 §16 variable-length integer at b[p:].
func quicVarint(b []byte, p int) (v uint64, n int, ok bool) {
	if p < 0 || p >= len(b) {
		return 0, 0, false
	}
	n = 1 << (b[p] >> 6)
	if p+n > len(b) {
		return 0, 0, false
	}
	v = uint64(b[p] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[p+i])
	}
	return v, n, true
}
