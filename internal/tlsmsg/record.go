package tlsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrNotRecord means the buffer is not a TLS record header.
	ErrNotRecord = errors.New("tlsmsg: not a TLS record")
	// ErrShortRecord means the record body declared by the header is not fully
	// present in the buffer.
	ErrShortRecord = errors.New("tlsmsg: record body is truncated")
	// ErrTrailingBytes means the buffer holds more than the one record. Splitting
	// it would silently drop the remainder, which is the stream-corruption class
	// this package exists to make impossible.
	ErrTrailingBytes = errors.New("tlsmsg: buffer holds more than one record")
	// ErrCutRange means a cut offset does not fall strictly inside the body.
	ErrCutRange = errors.New("tlsmsg: cut offset out of range")
	// ErrCutOrder means the cuts are not strictly increasing.
	ErrCutOrder = errors.New("tlsmsg: cuts are not strictly increasing")
)

// Header is a TLS record's 5-byte header.
type Header struct {
	Type    uint8
	Version uint16
	Length  int
}

// ParseHeader reads a record header. ok is false when fewer than 5 bytes are
// available.
func ParseHeader(b []byte) (Header, bool) {
	if len(b) < recHdrLen {
		return Header{}, false
	}
	return Header{
		Type:    b[0],
		Version: binary.BigEndian.Uint16(b[1:3]),
		Length:  int(binary.BigEndian.Uint16(b[3:recHdrLen])),
	}, true
}

// Bytes renders a record header.
func (h Header) Bytes() [5]byte {
	var out [5]byte
	out[0] = h.Type
	binary.BigEndian.PutUint16(out[1:3], h.Version)
	binary.BigEndian.PutUint16(out[3:], uint16(h.Length))
	return out
}

// SplitRecord reframes one TLS record into len(cuts)+1 structurally valid records
// carrying consecutive slices of the original body, concatenated into a single
// byte string that the caller writes with ONE Write. cuts are body-relative and
// strictly increasing.
//
// One Write matters: MEASUREMENTS.md §3.1 measured tlsrec2-1seg — two records
// inside a single TCP segment — passing 3/3, while every two-segment TCP split
// failed. TCP framing is irrelevant to this DPI, so the emitter needs no timing,
// no socket options and no root, and is byte-identical in proxy and TUN mode.
//
// The body bytes are never altered, only re-headed; a caller can therefore not
// corrupt a stream with this function, only fail to help.
func SplitRecord(rec []byte, cuts []int) ([]byte, error) {
	h, ok := ParseHeader(rec)
	if !ok {
		return nil, ErrNotRecord
	}
	total := recHdrLen + h.Length
	switch {
	case len(rec) < total:
		return nil, fmt.Errorf("%w: have %d, header declares %d", ErrShortRecord, len(rec), total)
	case len(rec) > total:
		return nil, fmt.Errorf("%w: have %d, record is %d", ErrTrailingBytes, len(rec), total)
	}
	body := rec[recHdrLen:total]

	prev := 0
	for _, c := range cuts {
		if c <= 0 || c >= h.Length {
			return nil, fmt.Errorf("%w: cut %d, body length %d", ErrCutRange, c, h.Length)
		}
		if c <= prev {
			return nil, fmt.Errorf("%w: %v", ErrCutOrder, cuts)
		}
		prev = c
	}

	out := make([]byte, 0, len(rec)+len(cuts)*recHdrLen)
	start := 0
	appendRec := func(end int) {
		hdr := Header{Type: h.Type, Version: h.Version, Length: end - start}.Bytes()
		out = append(out, hdr[:]...)
		out = append(out, body[start:end]...)
		start = end
	}
	for _, c := range cuts {
		appendRec(c)
	}
	appendRec(h.Length)
	return out, nil
}
