package tlsmsg

const (
	hsTypeClientHello = 0x01
	extServerName     = 0x0000
	sniTypeHostName   = 0x00

	tlsRandomLen = 32
	maxSNILen    = 255 // RFC 1035 §2.3.4: a domain name is at most 255 octets
)

// walker is a bounds-checked cursor over a ClientHello body. Every read either
// advances the cursor or sets bad; nothing indexes the slice directly, which is
// what makes a truncated or hostile hello a parse failure instead of a panic.
type walker struct {
	b   []byte
	p   int
	end int
	bad bool
}

func (w *walker) have(n int) bool {
	if w.bad || n < 0 || w.p+n > w.end {
		w.bad = true
		return false
	}
	return true
}

func (w *walker) u8() int {
	if !w.have(1) {
		return 0
	}
	v := int(w.b[w.p])
	w.p++
	return v
}

func (w *walker) u16() int {
	if !w.have(2) {
		return 0
	}
	v := int(w.b[w.p])<<8 | int(w.b[w.p+1])
	w.p += 2
	return v
}

func (w *walker) u24() int {
	if !w.have(3) {
		return 0
	}
	v := int(w.b[w.p])<<16 | int(w.b[w.p+1])<<8 | int(w.b[w.p+2])
	w.p += 3
	return v
}

func (w *walker) skip(n int) {
	if !w.have(n) {
		return
	}
	w.p += n
}

// parseClientHelloSNI walks a ClientHello and returns the host_name extension's
// value with its BODY-RELATIVE extent, or ("", -1, -1).
//
// Body-relative is not a style choice. MEASUREMENTS.md §3.2 expresses the rule
// that defeats the DPI as a position inside the first record's body, and the
// previous implementation's inert frag_window knob is what happens when a cut
// offset and the offset it is compared against live in different coordinate
// systems.
//
// The walk is GREASE tolerant by construction: unknown extension types are
// skipped by their declared length, so RFC 8701 values need no special case.
func parseClientHelloSNI(body []byte) (name string, start, end int) {
	w := &walker{b: body, end: len(body)}

	if w.u8() != hsTypeClientHello {
		return "", -1, -1
	}
	// A ClientHello may declare more than this record carries — it is legal for a
	// handshake message to span records. Clamp to what we actually have so a
	// hostname sitting inside the buffered prefix is still found.
	hsLen := w.u24()
	if limit := w.p + hsLen; !w.bad && limit < len(body) {
		w.end = limit
	}

	w.skip(2)            // legacy_version
	w.skip(tlsRandomLen) // random
	w.skip(w.u8())       // legacy_session_id
	w.skip(w.u16())      // cipher_suites
	w.skip(w.u8())       // legacy_compression_methods
	if w.bad {
		return "", -1, -1
	}

	extLen := w.u16()
	if w.bad {
		return "", -1, -1
	}
	extEnd := w.p + extLen
	if extEnd > w.end {
		extEnd = w.end
	}

	for w.p+4 <= extEnd {
		typ := w.u16()
		size := w.u16()
		if w.bad || w.p+size > extEnd {
			return "", -1, -1
		}
		if typ == extServerName {
			return parseSNIExtension(body, w.p, w.p+size)
		}
		w.p += size
	}
	return "", -1, -1
}

// parseSNIExtension reads a server_name extension body spanning body[from:to]
// and returns the first host_name entry's extent, absolute within body.
func parseSNIExtension(body []byte, from, to int) (string, int, int) {
	w := &walker{b: body, p: from, end: to}

	// The length is read on its own line on purpose: Go does not order a
	// non-call operand against a call in the same expression, so
	// "w.p + 2 + w.u16()" may read w.p either before or after u16 advances it.
	listLen := w.u16()
	listEnd := w.p + listLen
	if w.bad || listEnd > to {
		return "", -1, -1
	}
	for w.p+3 <= listEnd {
		kind := w.u8()
		size := w.u16()
		if w.bad || w.p+size > listEnd {
			return "", -1, -1
		}
		if kind == sniTypeHostName {
			if size == 0 || size > maxSNILen {
				return "", -1, -1
			}
			return string(body[w.p : w.p+size]), w.p, w.p + size
		}
		w.p += size
	}
	return "", -1, -1
}
