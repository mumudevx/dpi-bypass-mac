package ops

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// ErrNeedQUIC means the first message is not a QUIC Initial, so there is no
// datagram to shadow and no DCID to copy.
var ErrNeedQUIC = errors.New("ops: op requires a QUIC Initial datagram")

// quicFakeOp emits N decoy QUIC Initials with a low hop limit before the real
// datagram.
//
// DOSSIER §3 (P2) records the mechanism and why it is available here at all:
// byedpi's desync_udp is UNGATED on macOS — it calls setttl on the connected
// UDP socket and sends N fakes before the real datagram — so this works
// unprivileged on Darwin, unlike every TCP fake, which needs a sequence number
// the kernel will not give us. It needs to see the datagrams, which means
// SOCKS5 UDP ASSOCIATE or the TUN.
//
// Its efficacy against Turkish DPI is UNMEASURED. It is registered, tested and
// swept by the prober; it is on no shipped ladder.
//
// Each decoy carries the real datagram's version and DCID so a middlebox
// tracking the connection ID associates them with the flow, and a fixed filler
// payload so the plan is a pure function of its inputs — a probe result that
// cannot be reproduced byte for byte is not a measurement.
//
// The declared capabilities are the ones this op's PLAN actually needs, not the
// ones its mechanism is named after, because gate 3 is where a capability
// shortfall must be named and Strategy.CheckAgainst compares the DECLARED set
// while emit.Sender compares the DERIVED one.
//
// The segment contract amendment A7 asked for is settled: the decoys are
// strategy.SegFakeDatagram — ORDINARY WRITES on the connected socket with the
// hop limit lowered, which is what byedpi's desync_udp actually does — and not
// SegFakeRaw, which derives CapRawInject and is granted by nothing in this
// build (UDPTransport.InjectRaw is an unconditional error and nothing
// constructs a RawInjector). A decoy is not part of the payload, so SegStream
// cannot express it either: Plan's StreamBytes==Payload invariant fires on
// every such plan. SegFakeDatagram is exempt from that invariant by kind and
// derives CapDatagram, which only a datagram transport grants — so the op is
// emittable on a connected UDP socket and refused, by name, on a TCP one.
func quicFakeOp() strategy.Op {
	// What the plan will ask for, bit for bit: the decoy kind gives
	// CapDatagram, the hop limit on each decoy segment gives CapSockTTL, more
	// than one segment gives CapNoDelay, and CapUDPTTL keeps the op off a TCP
	// transport, which is the only place its datagram shape means anything.
	// UDPTransport grants all four.
	const caps = capsStream | strategy.CapUDPTTL | strategy.CapSockTTL | strategy.CapDatagram
	return newOp(strategy.OpDoc{
		Name:        "quicfake",
		Kind:        strategy.KindSide,
		Caps:        caps,
		Determinism: strategy.DetEmpirical,
		Params: []strategy.ParamDoc{
			{Name: "count", Default: "2", Probe: []string{"1", "2", "4"}, Doc: "decoy Initials to emit first"},
			{Name: "ttl", Default: "4", Probe: []string{"1", "2", "4", "8"}, Doc: "hop limit for the decoys"},
		},
		Summary: "send low-TTL decoy QUIC Initials ahead of the real datagram",
		Source:  "DOSSIER §3 (P2); efficacy against TR DPI unmeasured",
		Risk:    50,
	}, func(a strategy.Args) (strategy.Step, error) {
		count, err := a.IntRange("count", 2, 1, 8)
		if err != nil {
			return nil, err
		}
		ttl, err := a.IntRange("ttl", 4, 1, 255)
		if err != nil {
			return nil, err
		}
		return strategy.StepFunc("quicfake", caps, func(b *strategy.Builder) error {
			q, ok := tlsmsg.ParseQUICInitial(b.Payload)
			if !ok {
				return fmt.Errorf("%w: the first message is %s, %d bytes", ErrNeedQUIC, b.Meta.Proto, len(b.Payload))
			}
			// KindSide runs last, so a scheduling op may already have laid out
			// the real datagram. If nothing did, materialise it here: the decoys
			// have to go BEFORE it, and Builder.Build only fills in a default
			// segment when the schedule is entirely empty.
			if len(b.Segs) == 0 {
				b.Segs = []strategy.Segment{{Kind: strategy.SegStream, Data: b.Payload}}
			}
			fakes := make([]strategy.Segment, 0, count)
			for i := 0; i < count; i++ {
				fakes = append(fakes, strategy.Segment{
					Kind: strategy.SegFakeDatagram,
					Data: fakeInitial(b.Payload, q, byte(i)),
					TTL:  ttl,
					Note: fmt.Sprintf("decoy QUIC Initial %d/%d, hop limit %d", i+1, count, ttl),
				})
			}
			b.Segs = append(fakes, b.Segs...)
			b.Note("quicfake will emit %d decoy Initial(s) at ttl %d carrying the real DCID", count, ttl)
			return nil
		}), nil
	})
}

// fakeInitial builds one decoy datagram: the real packet's version and DCID, a
// zeroed SCID of the same length, no token, and filler where the protected
// payload would be. seed varies the filler so two decoys are not byte-identical
// — a middlebox that deduplicates identical datagrams would otherwise see one.
func fakeInitial(real []byte, q tlsmsg.QUICInitial, seed byte) []byte {
	dcid := real[q.DCIDStart:q.DCIDEnd]
	scidLen := q.SCIDEnd - q.SCIDStart

	out := make([]byte, 0, len(real))
	out = append(out, real[0]) // same long-header first byte: type, and PN length
	out = binary.BigEndian.AppendUint32(out, q.Version)
	out = append(out, byte(len(dcid)))
	out = append(out, dcid...)
	out = append(out, byte(scidLen))
	out = append(out, make([]byte, scidLen)...)
	out = append(out, 0x00) // token length 0, as a varint

	// The decoy is padded to the real datagram's size. A short Initial is
	// discarded by many stacks and is conspicuous to a middlebox counting
	// bytes; matching the real length keeps the two indistinguishable on the
	// only dimension that does not need decryption.
	body := len(real) - len(out) - 2
	body = min(max(body, 1), 0x3fff)                              // a 2-byte QUIC varint holds 14 bits
	out = binary.BigEndian.AppendUint16(out, uint16(body)|0x4000) // 2-byte varint length
	filler := make([]byte, body)
	for i := range filler {
		filler[i] = seed ^ byte(i)
	}
	return append(out, filler...)
}
