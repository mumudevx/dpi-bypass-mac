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

// tlsPadOp inflates the ClientHello with a padding extension placed before the
// server_name extension, pushing the hostname deeper into the record.
//
// Prober diagnostic only, never a ladder rung. PLAN's tune phase 3 sweeps the
// SNI to 300/600/1200/1500 bytes to learn how much of a flow the middlebox
// inspects; DOSSIER §3 notes the companion reading, that a minimum working pad
// approaching the MTU means the DPI is not reassembling and a plain split is
// the better answer. Neither reading belongs in a shipped ladder — the answer
// is a fact about the line, not a strategy.
func tlsPadOp() strategy.Op {
	return newOp(strategy.OpDoc{
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
		Summary: "inflate the ClientHello with a padding extension so the SNI sits deeper in the record",
		Source:  "PLAN tune phase 3; DOSSIER §3 (P2, diagnostic)",
		Risk:    25,
	}, func(a strategy.Args) (strategy.Step, error) {
		to, err := a.IntRange("to", 600, 1, maxRecordBody)
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("tlspad", strategy.CapStreamWrite, func(b *strategy.Builder) error {
			from := b.Meta.SNIStart
			out, err := padHello(b.Payload, b.Meta, to)
			if err != nil {
				return err
			}
			b.Payload = out
			// The record grew, so every body-relative offset a later reframing
			// op resolves — including sniEnd, which the §3.2 rule is stated in —
			// has moved.
			b.Reparse()
			b.Note("tlspad pushed the SNI from body offset %d to %d", from, to)
			return nil
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
