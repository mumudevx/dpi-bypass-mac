package strategy

import (
	"encoding/binary"
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// The stub op set. It mirrors the real emitter set's names, kinds, caps,
// determinism and requirements so that every composition and canonicalisation
// rule in this package is exercised against the shape internal/ops will
// actually register — this file is the executable half of that contract. The
// behaviour inside Compile is only as real as the builder tests need.

func init() { registerStubs(Default()) }

type stubOp struct {
	Base
	compile func(a Args) (Step, error)
}

func (o stubOp) Compile(a Args) (Step, error) { return o.compile(a) }

func newStub(d OpDoc, c func(a Args) (Step, error)) stubOp {
	return stubOp{Base: Base{D: d}, compile: c}
}

// requiredPos reads a mandatory position parameter.
func requiredPos(op string, a Args) (Pos, error) {
	if _, ok := a["pos"]; !ok {
		return Pos{}, fmt.Errorf("%w: %s needs pos", ErrBadValue, op)
	}
	return a.Pos("pos", Pos{})
}

func registerStubs(r *Registry) {
	streamCaps := CapStreamWrite | CapNoDelay

	r.Register(newStub(OpDoc{
		Name: "hostcase", Kind: KindMutate, Caps: CapStreamWrite,
		Determinism: DetEmpirical, Requires: ReqHost,
		Summary: "flip the case of the Host header value", Source: "DOSSIER §3", Risk: 10,
	}, func(Args) (Step, error) {
		return StepFunc("hostcase", CapStreamWrite, func(b *Builder) error {
			if !b.Meta.HasHost() {
				return ErrNeedHost
			}
			for i := b.Meta.HostStart; i < b.Meta.HostEnd; i++ {
				if c := b.Payload[i]; c >= 'a' && c <= 'z' {
					b.Payload[i] = c - 32
				}
			}
			return nil // length preserved, so no reparse is needed
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "hostdot", Kind: KindMutate, Caps: CapStreamWrite,
		Determinism: DetEmpirical, Requires: ReqHost,
		Summary: "append a trailing dot to the Host header value", Source: "DOSSIER §3", Risk: 15,
	}, func(Args) (Step, error) {
		return StepFunc("hostdot", CapStreamWrite, func(b *Builder) error {
			if !b.Meta.HasHost() {
				return ErrNeedHost
			}
			out := make([]byte, 0, len(b.Payload)+1)
			out = append(out, b.Payload[:b.Meta.HostEnd]...)
			out = append(out, '.')
			out = append(out, b.Payload[b.Meta.HostEnd:]...)
			b.Payload = out
			b.Reparse() // the payload grew: every downstream offset moved
			return nil
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "hostpad", Kind: KindMutate, Caps: CapStreamWrite,
		Determinism: DetEmpirical, Requires: ReqHost,
		Params:  []ParamDoc{{Name: "len", Default: "1", Probe: []string{"1", "8"}, Doc: "spaces to insert"}},
		Summary: "pad the Host header value with leading spaces", Risk: 20,
	}, func(a Args) (Step, error) {
		n, err := a.IntRange("len", 1, 1, 64)
		if err != nil {
			return nil, err
		}
		return StepFunc("hostpad", CapStreamWrite, func(b *Builder) error {
			if !b.Meta.HasHost() {
				return ErrNeedHost
			}
			pad := make([]byte, n)
			for i := range pad {
				pad[i] = ' '
			}
			out := make([]byte, 0, len(b.Payload)+n)
			out = append(out, b.Payload[:b.Meta.HostStart]...)
			out = append(out, pad...)
			out = append(out, b.Payload[b.Meta.HostStart:]...)
			b.Payload = out
			b.Reparse()
			return nil
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "tlsfrag", Kind: KindReframe, Caps: streamCaps,
		Determinism: DetRuleBased, Requires: ReqComplete | ReqSNI,
		Params: []ParamDoc{{Name: "pos", Probe: []string{"snimid", "sniend-1"},
			Doc: "body-relative cut position; must be <= sniEnd-1"}},
		Summary: "reframe the first TLS record so the SNI is not complete inside it",
		Source:  "MEASUREMENTS.md §3.2", Risk: 45,
	}, func(a Args) (Step, error) {
		p, err := requiredPos("tlsfrag", a)
		if err != nil {
			return nil, err
		}
		return StepFunc("tlsfrag", streamCaps, func(b *Builder) error {
			cut, ok := p.Resolve(b.Meta)
			if !ok {
				return fmt.Errorf("%w: pos %s does not resolve against this message", ErrNeedSNI, p)
			}
			return b.ReframeFirstRecord([]int{cut})
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "tlsevery", Kind: KindReframe, Caps: streamCaps,
		Determinism: DetRuleBased, Requires: ReqComplete,
		Params: []ParamDoc{{Name: "period", Probe: []string{"16", "64"},
			Doc: "record size; the first record ends here, so it must be <= sniEnd-1"}},
		Summary: "reframe the first record periodically", Source: "MEASUREMENTS.md §3", Risk: 45,
	}, func(a Args) (Step, error) {
		if _, ok := a["period"]; !ok {
			return nil, fmt.Errorf("%w: tlsevery needs period", ErrBadValue)
		}
		n, err := a.IntRange("period", 0, 1, 1<<14)
		if err != nil {
			return nil, err
		}
		return StepFunc("tlsevery", streamCaps, func(b *Builder) error {
			var cuts []int
			for c := n; c < b.Meta.BodyLen; c += n {
				cuts = append(cuts, c)
			}
			if len(cuts) == 0 {
				return fmt.Errorf("%w: period %d exceeds the record body (%d)", ErrBadValue, n, b.Meta.BodyLen)
			}
			return b.ReframeFirstRecord(cuts)
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "chunk", Kind: KindSchedule, Caps: streamCaps,
		Determinism: DetEmpirical, Requires: ReqComplete,
		Params:  []ParamDoc{{Name: "size", Probe: []string{"12", "4"}, Doc: "bytes per write"}},
		Summary: "fixed-size write loop", Source: "MEASUREMENTS.md §3.4", Risk: 40,
	}, func(a Args) (Step, error) {
		if _, ok := a["size"]; !ok {
			return nil, fmt.Errorf("%w: chunk needs size", ErrBadValue)
		}
		n, err := a.IntRange("size", 0, 1, 1<<16)
		if err != nil {
			return nil, err
		}
		return StepFunc("chunk", streamCaps, func(b *Builder) error {
			var offs []int
			for o := n; o < len(b.Payload); o += n {
				offs = append(offs, o)
			}
			return b.SplitAt(offs...)
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "split", Kind: KindSchedule, Caps: streamCaps,
		Determinism: DetEmpirical,
		Params:      []ParamDoc{{Name: "pos", Probe: []string{"1", "snimid"}, Doc: "split offset"}},
		Summary:     "plain N-segment TCP split", Source: "MEASUREMENTS.md §3.1 (0/5 on TT)", Risk: 25,
	}, func(a Args) (Step, error) {
		p, err := requiredPos("split", a)
		if err != nil {
			return nil, err
		}
		return StepFunc("split", streamCaps, func(b *Builder) error {
			off, ok := p.Resolve(b.Meta)
			if !ok {
				return fmt.Errorf("%w: pos %s does not resolve", ErrNeedSNI, p)
			}
			return b.SplitAt(off)
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "disorder", Kind: KindSchedule, Caps: streamCaps | CapSockTTL,
		Determinism: DetEmpirical,
		Params: []ParamDoc{
			{Name: "pos", Probe: []string{"1", "3"}, Doc: "split offset"},
			{Name: "ttl", Default: "1", Doc: "TTL of the leading segment"},
		},
		Summary: "send the head with IP_TTL=1 so only the DPI sees it",
		Source:  "MEASUREMENTS.md §3.5 (0/10 on TT)", Risk: 60,
	}, func(a Args) (Step, error) {
		p, err := requiredPos("disorder", a)
		if err != nil {
			return nil, err
		}
		ttl, err := a.IntRange("ttl", 1, 1, 255)
		if err != nil {
			return nil, err
		}
		return StepFunc("disorder", streamCaps|CapSockTTL, func(b *Builder) error {
			off, ok := p.Resolve(b.Meta)
			if !ok {
				return fmt.Errorf("%w: pos %s does not resolve", ErrNeedSNI, p)
			}
			if err := b.SplitAt(off); err != nil {
				return err
			}
			return b.SetSegTTL(0, ttl)
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "oob", Kind: KindSchedule, Caps: streamCaps | CapOOB,
		Determinism: DetEmpirical,
		Params: []ParamDoc{
			{Name: "pos", Probe: []string{"1", "3"}, Doc: "split offset"},
			{Name: "junk", Default: "1", Doc: "the out-of-band byte"},
		},
		Summary: "MSG_OOB junk byte at a split point", Source: "MEASUREMENTS.md §5.1 (0/20 fragile)", Risk: 90,
	}, func(a Args) (Step, error) {
		p, err := requiredPos("oob", a)
		if err != nil {
			return nil, err
		}
		junk, err := a.IntRange("junk", 1, 0, 255)
		if err != nil {
			return nil, err
		}
		return StepFunc("oob", streamCaps|CapOOB, func(b *Builder) error {
			off, ok := p.Resolve(b.Meta)
			if !ok {
				return fmt.Errorf("%w: pos %s does not resolve", ErrNeedSNI, p)
			}
			if err := b.SplitAt(off); err != nil {
				return err
			}
			return b.MarkOOB(0, byte(junk))
		}), nil
	}))

	r.Register(newStub(OpDoc{
		Name: "quicfake", Kind: KindSide, Caps: CapUDPTTL,
		Determinism: DetEmpirical,
		Params: []ParamDoc{
			{Name: "count", Default: "2", Doc: "fake Initials to emit"},
			{Name: "ttl", Default: "4", Doc: "hop limit for the fakes"},
		},
		Summary: "low-TTL fake QUIC Initials alongside the real datagram", Risk: 50,
	}, func(a Args) (Step, error) {
		count, err := a.IntRange("count", 2, 1, 8)
		if err != nil {
			return nil, err
		}
		ttl, err := a.IntRange("ttl", 4, 1, 255)
		if err != nil {
			return nil, err
		}
		return StepFunc("quicfake", CapUDPTTL, func(b *Builder) error {
			b.Note("would emit %d fake QUIC Initials at ttl %d", count, ttl)
			return nil
		}), nil
	}))

	// Registered so that asking for it produces a mechanical reason instead of
	// "unknown op". PLAN "Capabilities per mode": struct tcp_connection_info on
	// Darwin has no snd_nxt field, so CapRawSeq can never be granted.
	r.Register(newStub(OpDoc{
		Name: "seqovl", Kind: KindSchedule, Caps: CapRawSeq,
		Determinism: DetEmpirical,
		Params:      []ParamDoc{{Name: "pos", Doc: "overlap offset"}},
		Summary:     "sequence-overlapping decoy segment",
		Rejected: "needs the upstream snd_nxt, and struct tcp_connection_info in " +
			"netinet/tcp.h has no such field on macOS, so CapRawSeq can never be granted",
		Risk: 100,
	}, func(Args) (Step, error) {
		return StepFunc("seqovl", CapRawSeq, func(*Builder) error { return nil }), nil
	}))
}

// allCaps is what a transport with every capability offers, so a test can
// exercise an op without the capability gate getting in the way first.
const allCaps = CapStreamWrite | CapNoDelay | CapSockTTL | CapOOB | CapUDPTTL | CapRawInject | CapRawSeq

// tlsFixture builds a TLS record whose body is bodyLen bytes with a synthetic
// SNI extent at [sniStart, sniEnd). The default geometry is the one
// MEASUREMENTS.md §3.2 measured: body=1497, sni at [112,122).
func tlsFixture(bodyLen, sniStart, sniEnd int) ([]byte, tlsmsg.Meta) {
	buf := make([]byte, 5+bodyLen)
	buf[0], buf[1], buf[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(buf[3:5], uint16(bodyLen))
	for i := 5; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	m := tlsmsg.Meta{
		Proto: tlsmsg.ProtoTLS, DstPort: 443, Complete: true,
		ServerName: "discord.com",
		BodyOff:    5, BodyLen: bodyLen,
		SNIStart: sniStart, SNIEnd: sniEnd,
		HostStart: -1, HostEnd: -1, HeaderEnd: -1,
	}
	copy(m.RecHdr[:], buf[:5])
	return buf, m
}

// measuredFixture is MEASUREMENTS.md §3.2's exact geometry.
func measuredFixture() ([]byte, tlsmsg.Meta) { return tlsFixture(1497, 112, 122) }

// realHello builds a genuine minimal ClientHello carrying name, so a test can
// check that this package's coordinates agree with tlsmsg.Parse's rather than
// only with a hand-written Meta.
func realHello(name string) []byte {
	var ext []byte
	ext = append(ext, 0x00, 0x00) // extension_type: server_name
	sni := []byte{0x00}           // name_type: host_name
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(sni)))
	list = append(list, sni...)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)))
	ext = append(ext, list...)

	var body []byte
	body = append(body, 0x03, 0x03)             // legacy_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id length
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression_methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// httpFixture builds a plaintext request whose Host header value is host.
func httpFixture(host string) ([]byte, tlsmsg.Meta) {
	req := "GET /x HTTP/1.1\r\nHost: " + host + "\r\nAccept: */*\r\n\r\n"
	return []byte(req), tlsmsg.Parse([]byte(req), 80)
}
