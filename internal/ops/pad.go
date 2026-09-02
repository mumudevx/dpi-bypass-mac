package ops

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// TLS constants used by the padding rewrite.
const (
	extPadding    uint16 = 21 // RFC 7685
	extServerName uint16 = 0
	extHdrLen            = 4     // 2-byte type + 2-byte length
	maxRecordBody        = 16384 // RFC 8446 §5.1: a plaintext record body is at most 2^14
)

var (
	// ErrNotClientHello means the first record's body is not a structurally
	// walkable ClientHello, so its extension block cannot be rewritten.
	ErrNotClientHello = errors.New("ops: first record is not a walkable ClientHello")
	// ErrAlreadyPadded means the hello already carries a padding extension.
	// RFC 8446 §4.2 forbids two extensions of the same type, and growing the
	// existing one would not move a hostname that sits before it, so this is
	// refused rather than silently turned into a no-op.
	ErrAlreadyPadded = errors.New("ops: ClientHello already carries a padding extension")
)

// padPointless is why tlspad can never be selected. It is stated once, here,
// and reaches the user through strategy.ErrOpRejected at PARSE time.
//
// dpb is a byte relay. The client's own crypto/tls composed the ClientHello and
// has already fed those exact bytes into its handshake transcript, so a padding
// extension inserted in flight changes the message the server hashes and not
// the one the client hashed: the TLS 1.3 key schedule diverges and the
// handshake dies with "local error: tls: bad record MAC". Proved with the
// network removed entirely — a Go tls.Server and tls.Client over 127.0.0.1 with
// the rewrite in between, structurally perfect output, both ends failing — and
// live, where tlspad:to=600 is 0/2 against an unblocked control that plain
// passes 2/2.
//
// That makes it worse than useless as PLAN's tune-phase-3 instrument: it reads
// identically on a censored and an open line, which is exactly the inert-knob
// class MEASUREMENTS.md §3.5 exists to forbid, and dpb reported the purely
// local alert to the user as verdict RESET — a client-side bug presented as
// censorship.
//
// It is REGISTERED rather than deleted for the same reason as the unreachable
// family: a user pasting a strategy string from a forum must be told which
// mechanism cannot work here and why, and "unknown op" sends them in the
// opposite direction. The measurement PLAN wanted — how deep does this
// middlebox inspect — needs the padded hello sent as a low-TTL DECOY with the
// real, unmodified hello following it, which needs a decoy segment kind this
// build does not have. padHello below is that decoy's payload, kept and tested
// so the respecification has something to stand on.
const padPointless = "rewrites the ClientHello in flight, but the client's own crypto/tls has already " +
	"committed those bytes to its handshake transcript, so an inserted padding extension desynchronises " +
	"the TLS 1.3 key schedule and every connection dies with `bad record MAC` no matter what the DPI " +
	"does — a byte relay cannot pad a hello it did not originate. The inspection-depth measurement this " +
	"was for needs the padded hello as a low-TTL DECOY followed by the real one, which this build has no " +
	"segment kind for"

// tlsPadOp inflates the ClientHello with a padding extension placed before the
// server_name extension, pushing the hostname deeper into the record — and is
// refused before it compiles. See padPointless.
func tlsPadOp() strategy.Op {
	d := strategy.OpDoc{
		Name:        "tlspad",
		Kind:        strategy.KindMutate,
		Caps:        strategy.CapStreamWrite,
		Determinism: strategy.DetEmpirical,
		Requires:    strategy.ReqComplete | strategy.ReqSNI,
		Params: []strategy.ParamDoc{{
			Name:    "to",
			Default: "600",
			Probe:   []string{"300", "600", "1200", "1500"},
			Doc:     "body offset to push the SNI hostname to",
		}},
		Summary:  "inflate the ClientHello with a padding extension so the SNI sits deeper in the record",
		Source:   "PLAN tune phase 3; refuted by direct measurement, see padPointless",
		Risk:     100,
		Rejected: padPointless,
	}
	return newOp(d, func(strategy.Args) (strategy.Step, error) {
		// Unreachable: Registry.Get refuses a Rejected op before it compiles.
		// Kept honest rather than returning nil, so a caller that bypasses Get
		// still cannot emit a desynchronising rewrite.
		return strategy.StepFunc(d.Name, d.Caps, func(*strategy.Builder) error {
			return fmt.Errorf("%w: %s — %s", strategy.ErrOpRejected, d.Name, d.Rejected)
		}), nil
	})
}

// padHello rewrites the first TLS record of payload so the SNI hostname starts
// at body offset `to`. Every length it touches is re-derived and bounds-checked;
// a rewrite it cannot complete is an error, never a partially patched hello.
func padHello(payload []byte, m tlsmsg.Meta, to int) ([]byte, error) {
	if m.Proto != tlsmsg.ProtoTLS || !m.Complete {
		return nil, fmt.Errorf("%w: proto %s, complete %v", strategy.ErrNeedComplete, m.Proto, m.Complete)
	}
	if !m.HasSNI() {
		return nil, fmt.Errorf("%w: tlspad places its padding before the server_name extension", strategy.ErrNeedSNI)
	}
	end := m.RecordEnd()
	if m.BodyOff < 5 || end > len(payload) || m.BodyOff >= end {
		return nil, fmt.Errorf("%w: record ends at %d, payload is %d bytes", strategy.ErrNeedComplete, end, len(payload))
	}
	body := payload[m.BodyOff:end]

	delta := to - m.SNIStart
	if delta < extHdrLen {
		return nil, fmt.Errorf("%w: to=%d is only %d bytes past the current SNI offset %d; the smallest "+
			"padding extension is %d bytes", strategy.ErrBadValue, to, delta, m.SNIStart, extHdrLen)
	}
	if len(body)+delta > maxRecordBody {
		return nil, fmt.Errorf("%w: padding to %d would make a %d-byte record body, over the %d-byte "+
			"TLS limit", strategy.ErrBadValue, to, len(body)+delta, maxRecordBody)
	}

	extLenOff, exts, err := walkHelloExtensions(body)
	if err != nil {
		return nil, err
	}
	sniOff := -1
	for _, e := range exts {
		switch e.typ {
		case extPadding:
			return nil, fmt.Errorf("%w: at body offset %d", ErrAlreadyPadded, m.BodyOff+e.off)
		case extServerName:
			sniOff = e.off
		}
	}
	if sniOff < 0 {
		return nil, fmt.Errorf("%w: no server_name extension in the walked hello", ErrNotClientHello)
	}

	pad := make([]byte, delta)
	binary.BigEndian.PutUint16(pad[0:2], extPadding)
	binary.BigEndian.PutUint16(pad[2:4], uint16(delta-extHdrLen))

	out := make([]byte, 0, len(payload)+delta)
	out = append(out, payload[:m.BodyOff]...)
	out = append(out, body[:sniOff]...)
	out = append(out, pad...)
	out = append(out, body[sniOff:]...)
	out = append(out, payload[end:]...)

	// Three nested lengths all describe the same bytes and all must move
	// together: the record body, the handshake message, and the extension block.
	nb := out[m.BodyOff : m.BodyOff+len(body)+delta]
	if err := addUint16(out[m.BodyOff-2:m.BodyOff], delta, maxRecordBody); err != nil {
		return nil, fmt.Errorf("record length: %w", err)
	}
	if err := addUint24(nb[1:4], delta); err != nil {
		return nil, fmt.Errorf("handshake length: %w", err)
	}
	if err := addUint16(nb[extLenOff:extLenOff+2], delta, 0xffff); err != nil {
		return nil, fmt.Errorf("extensions length: %w", err)
	}
	return out, nil
}

func addUint16(b []byte, delta, max int) error {
	v := int(binary.BigEndian.Uint16(b)) + delta
	if v < 0 || v > max || v > 0xffff {
		return fmt.Errorf("%w: %d is out of range", strategy.ErrBadValue, v)
	}
	binary.BigEndian.PutUint16(b, uint16(v))
	return nil
}

func addUint24(b []byte, delta int) error {
	v := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	v += delta
	if v < 0 || v > 0xffffff {
		return fmt.Errorf("%w: %d is out of range", strategy.ErrBadValue, v)
	}
	b[0], b[1], b[2] = byte(v>>16), byte(v>>8), byte(v)
	return nil
}

type extent struct {
	typ uint16
	off int // body-relative offset of the extension's 2-byte type field
	len int // declared length of the extension's data
}

// walkHelloExtensions locates the extension block of a ClientHello record body
// and every extension in it. Every read is bounds-checked against the buffer,
// never against a declared length, so a hostile or truncated hello yields an
// error rather than an out-of-range index.
func walkHelloExtensions(body []byte) (extLenOff int, exts []extent, err error) {
	fail := func(what string) (int, []extent, error) {
		return 0, nil, fmt.Errorf("%w: %s", ErrNotClientHello, what)
	}
	if len(body) < 4 || body[0] != 0x01 {
		return fail("not a handshake ClientHello")
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+msgLen > len(body) {
		return fail(fmt.Sprintf("handshake declares %d bytes, record body holds %d", msgLen, len(body)-4))
	}
	p := 4 + 2 + 32 // handshake header, legacy_version, random
	if p >= len(body) {
		return fail("truncated before the session id")
	}
	p += 1 + int(body[p]) // session_id
	if p+2 > len(body) {
		return fail("truncated before the cipher suites")
	}
	p += 2 + int(binary.BigEndian.Uint16(body[p:p+2])) // cipher_suites
	if p >= len(body) {
		return fail("truncated before the compression methods")
	}
	p += 1 + int(body[p]) // compression_methods
	if p+2 > len(body) {
		return fail("no extension block")
	}
	extLenOff = p
	total := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if p+total > len(body) {
		return fail(fmt.Sprintf("extension block declares %d bytes, %d remain", total, len(body)-p))
	}
	limit := p + total
	for p+extHdrLen <= limit {
		typ := binary.BigEndian.Uint16(body[p : p+2])
		n := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		if p+extHdrLen+n > limit {
			return fail(fmt.Sprintf("extension %#04x declares %d bytes past the block", typ, n))
		}
		exts = append(exts, extent{typ: typ, off: p, len: n})
		p += extHdrLen + n
	}
	if p != limit {
		return fail("extension block does not end on an extension boundary")
	}
	return extLenOff, exts, nil
}
