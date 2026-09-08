package testcensor

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// ErrCorrupt is the sentinel every integrity failure wraps.
//
// A bypass tool that corrupts a stream is worse than no bypass tool: the user
// cannot tell a mangled handshake from a censored one, and will conclude the
// site is blocked. Every strategy × model combination in the test matrix runs
// through here.
var ErrCorrupt = errors.New("testcensor: stream integrity violated")

// CheckIntegrity asserts that the bytes the receiver reassembled are exactly the
// bytes the sender wrote.
//
// This is the categorical check: it catches a dropped segment, a duplicated
// retry, a reordered write and an out-of-band byte that leaked into the stream,
// all with one comparison and without knowing anything about the protocol.
func CheckIntegrity(sent, got []byte) error {
	if bytes.Equal(sent, got) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrCorrupt, diff(sent, got))
}

// CheckHandshakeIntegrity asserts that a reframed TLS stream still carries the
// original handshake.
//
// Reframing changes the record layer on purpose, so byte identity is the wrong
// question for tlsfrag and tlsevery: what must hold is that a conforming
// receiver, concatenating the record bodies, reconstructs the identical
// ClientHello. That is the property MEASUREMENTS.md §3.2 depends on — the DPI is
// fooled while the server is not — and the property tlsmsg.SplitRecord is built
// to make unbreakable.
func CheckHandshakeIntegrity(orig, got []byte) error {
	wantType, want, err := recordBodies(orig)
	if err != nil {
		return fmt.Errorf("%w: original: %w", ErrCorrupt, err)
	}
	gotType, have, err := recordBodies(got)
	if err != nil {
		return fmt.Errorf("%w: received: %w", ErrCorrupt, err)
	}
	if wantType != gotType {
		return fmt.Errorf("%w: record type %#x became %#x", ErrCorrupt, wantType, gotType)
	}
	if !bytes.Equal(want, have) {
		return fmt.Errorf("%w: handshake body changed: %s", ErrCorrupt, diff(want, have))
	}
	return nil
}

// recordBodies concatenates the bodies of every complete record in b and
// returns the first record's type.
func recordBodies(b []byte) (uint8, []byte, error) {
	if len(b) < 5 {
		return 0, nil, fmt.Errorf("%d bytes is not a TLS record", len(b))
	}
	var out []byte
	var typ uint8
	first := true
	for len(b) > 0 {
		h, ok := tlsmsg.ParseHeader(b)
		if !ok {
			return 0, nil, fmt.Errorf("trailing %d bytes are not a record header", len(b))
		}
		if len(b) < 5+h.Length {
			return 0, nil, fmt.Errorf("record declares %d body bytes, %d present", h.Length, len(b)-5)
		}
		if first {
			typ, first = h.Type, false
		} else if h.Type != typ {
			return 0, nil, fmt.Errorf("record type changed from %#x to %#x mid-stream", typ, h.Type)
		}
		out = append(out, b[5:5+h.Length]...)
		b = b[5+h.Length:]
	}
	return typ, out, nil
}

// diff names the first divergence in terms a failing test can act on.
func diff(want, got []byte) string {
	n := min(len(want), len(got))
	for i := range n {
		if want[i] != got[i] {
			return fmt.Sprintf("byte %d: want %#02x, got %#02x (lengths %d and %d)",
				i, want[i], got[i], len(want), len(got))
		}
	}
	switch {
	case len(got) < len(want):
		return fmt.Sprintf("truncated after %d bytes, want %d (%d missing)", len(got), len(want), len(want)-len(got))
	default:
		return fmt.Sprintf("%d extra bytes after the expected %d", len(got)-len(want), len(want))
	}
}
