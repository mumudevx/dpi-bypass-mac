// Package testcensor is a censor you can run inside `go test`.
//
// It exists because the thing this tool is built to defeat lives on one ISP in
// one country and cannot be brought into CI. Every claim the implementation
// makes about DPI behaviour is therefore restated here as an executable
// hypothesis: a Model with a doc comment naming its source and its confidence,
// and a Middlebox that enforces it on an in-process connection. A scenario test
// then reads as a claim — "tlsfrag:pos=snimid evades this model, split:pos=snimid
// does not" — and the claim breaks when the code regresses, never when the
// network moves.
//
// The distinction matters and is stated plainly in MEASUREMENTS.md §4: these
// models test our understanding of the DPI, not the DPI. TT2026 reproduces the
// mechanism established by 66 shuffled trials in §3.2. It does not reproduce
// §3.4's chunking results, because no simple model explains them — see the note
// on TT2026 for why pretending otherwise would be worse than useless.
package testcensor

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// Action is what the modelled middlebox does to a flow it has matched.
type Action uint8

const (
	// ActionPass forwards the flow untouched.
	ActionPass Action = iota
	// ActionReset injects a TCP RST, which is what Türk Telekom does
	// (MEASUREMENTS.md §1: curl reports "connection reset" on a blocked SNI).
	ActionReset
	// ActionDrop blackholes the flow silently: the client sees a timeout, not an
	// error. This is the DNS-side behaviour (§2, per-QNAME UDP drop) and the
	// shape a prober must distinguish from a reset.
	ActionDrop
	// ActionEOF closes the connection cleanly. Six of the ten fragile Turkish
	// endpoints in §5 fail this way ("handshake: EOF").
	ActionEOF
	// ActionAlert sends a fatal TLS alert and closes, modelling
	// www.yapikredi.com.tr, which answers a record-split ClientHello with
	// "remote error: tls: illegal parameter" (§5).
	ActionAlert
)

var actionNames = [...]string{"pass", "reset", "drop", "eof", "alert"}

func (a Action) String() string {
	if int(a) >= len(actionNames) {
		return "invalid"
	}
	return actionNames[a]
}

// Verdict is one middlebox decision about one flow.
type Verdict struct {
	Action Action
	Reason string // why, in words a failing test can print
	Match  string // the hostname or prefix that triggered it, if any
}

// Blocked reports whether the verdict does anything other than forward.
func (v Verdict) Blocked() bool { return v.Action != ActionPass }

func (v Verdict) String() string {
	if v.Match == "" {
		return fmt.Sprintf("%s (%s)", v.Action, v.Reason)
	}
	return fmt.Sprintf("%s %s (%s)", v.Action, v.Match, v.Reason)
}

// Model is a hypothesis about a middlebox, expressed as data.
//
// The fields are deliberately orthogonal so a test can vary one at a time and
// name which property of the censor a strategy actually depends on. A strategy
// that only survives with RecordAware=false, for instance, is relying on a naive
// string matcher and will not survive Türk Telekom.
type Model struct {
	Name string
	// Doc records the hypothesis' provenance and confidence. Printed by failing
	// scenario tests so the reader knows whether they are looking at a measured
	// fact or a guess.
	Doc string

	// Ports the middlebox inspects. Empty means every port.
	Ports []int
	// Blocked hostnames, matched label-anchored: "discord.com" matches
	// "discord.com" and "cdn.discord.com" but never "notdiscord.com".
	Blocked []string
	// BlockedAddrs are destinations blocked by address regardless of payload —
	// the ShapeIPBlock case a prober must detect and stop on, rather than
	// hunting for a strategy that cannot exist.
	BlockedAddrs []netip.Prefix

	// RecordAware means the middlebox understands the TLS record layer. When
	// false it merely scans the reassembled byte stream for a hostname, which is
	// the naive model any hostname-splitting emitter defeats.
	RecordAware bool
	// FirstRecordOnly is the measured Türk Telekom rule (§3.2): only the FIRST
	// TLS record of a connection is parsed as a ClientHello. If the hostname is
	// not complete inside it, the flow is never matched.
	FirstRecordOnly bool
	// ReassembleTCP means segment boundaries are invisible to the middlebox: it
	// concatenates the client's writes before parsing. Measured true on Türk
	// Telekom (§3.1) — every two-segment TCP split fails, including one cut
	// inside the hostname.
	ReassembleTCP bool
	// InspectBytes caps how much of a flow is examined before the middlebox
	// gives up and forwards. 0 means unlimited.
	InspectBytes int
	// MinTTL is the modelled IP hop count from the client to the ORIGIN. A
	// segment written with a lower TTL is seen by the middlebox — which sits
	// closer — but never reaches the origin. 0 disables TTL modelling entirely,
	// which is the honest default: an in-process stream has no hop count.
	MinTTL int

	// RejectSpanningRecords models a TLS terminator that refuses a handshake
	// message split across two records. Legal per RFC 8446 §5.1, but 10 of 41
	// Turkish hosts tested in §5 reject it, and all ten are banks or .gov.tr.
	RejectSpanningRecords bool
	// RejectOOB models an endpoint broken by an urgent byte in the stream. §5.1
	// measured oob-at-1 and oob-at-3 at 0/20 on the fragile hosts: the most
	// destructive rung on the ladder.
	RejectOOB bool

	// Action is taken when any predicate above fires.
	Action Action
	// AlertDesc is the TLS alert description for ActionAlert.
	AlertDesc uint8

	// LossRate is the probability that a connection fails mid-handshake for
	// reasons that are not censorship. It models end-to-end packet loss at the
	// only granularity an in-process reliable stream can express — the
	// connection — and exists so a prober can be shown a lossy but uncensored
	// network and be required NOT to invent a winner.
	LossRate float64
}

// TLS alert descriptions used by the models here (RFC 8446 §6).
const (
	AlertIllegalParameter uint8 = 47
	AlertHandshakeFailure uint8 = 40
	AlertDecodeError      uint8 = 50
)

const (
	alertLevelFatal = 2
	recTypeAlert    = 0x15
)

// AlertRecord renders a fatal TLS alert record.
func AlertRecord(desc uint8) []byte {
	return []byte{recTypeAlert, 0x03, 0x03, 0x00, 0x02, alertLevelFatal, desc}
}

// inspects reports whether this model looks at traffic to the given port.
func (m Model) inspects(port int) bool {
	if len(m.Ports) == 0 {
		return true
	}
	for _, p := range m.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// blocks reports whether name is covered by the blocklist, matching on label
// boundaries so that "bank.com" never matches "evilbank.com".
func (m Model) blocks(name string) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, b := range m.Blocked {
		b = strings.ToLower(strings.TrimSuffix(b, "."))
		if b == "" {
			continue
		}
		if h == b || strings.HasSuffix(h, "."+b) {
			return b, true
		}
	}
	return "", false
}

// blocksAddr reports whether the destination address is blocked outright.
func (m Model) blocksAddr(a netip.Addr) (string, bool) {
	if !a.IsValid() {
		return "", false
	}
	for _, p := range m.BlockedAddrs {
		if p.Contains(a.Unmap()) {
			return p.String(), true
		}
	}
	return "", false
}

func (m Model) action() Action {
	if m.Action == ActionPass {
		return ActionReset
	}
	return m.Action
}

// Inspector is the per-flow state of a Model. One connection, one Inspector.
//
// It is exported so a test can drive the pure decision logic with no sockets at
// all; Middlebox wires it to a real net.Conn.
type Inspector struct {
	m    Model
	port int

	buf     []byte
	fed     int // bytes offered to the inspection window, TTL-dropped included
	oob     bool
	decided bool
	v       Verdict
	name    string
}

// Inspect starts a flow. port is the destination port, used only to decide
// whether this model looks at the flow at all.
func (m Model) Inspect(port int) *Inspector {
	in := &Inspector{m: m, port: port}
	if !m.inspects(port) {
		in.decide(Verdict{Reason: fmt.Sprintf("port %d is not inspected", port)})
	}
	return in
}

// Dst applies the address-level predicate. It is separate from Client because
// an IP-level block fires before the client says anything, which is exactly the
// property that distinguishes it from an SNI block.
func (i *Inspector) Dst(a netip.Addr) Verdict {
	if i.decided {
		return i.v
	}
	if p, ok := i.m.blocksAddr(a); ok {
		return i.decide(Verdict{
			Action: i.m.action(), Match: p,
			Reason: "destination address is blocked regardless of payload",
		})
	}
	return i.v
}

// ServerName is the hostname the middlebox extracted, if any.
func (i *Inspector) ServerName() string { return i.name }

// Verdict is the decision so far. Before the first record completes this is the
// zero Verdict, meaning "still watching".
func (i *Inspector) Verdict() Verdict { return i.v }

// Decided reports whether the flow's fate is settled.
func (i *Inspector) Decided() bool { return i.decided }

func (i *Inspector) decide(v Verdict) Verdict {
	i.decided, i.v = true, v
	return v
}

// Client feeds one client-to-server segment, exactly as the client wrote it.
// ttl is the IP TTL the segment was written with, or 0 for the socket default.
//
// deliver reports whether the segment reaches the origin. It is false for a
// segment whose TTL expires before the origin (the fake-segment mechanism) and
// for every segment after a blocking verdict.
func (i *Inspector) Client(seg []byte, ttl int) (v Verdict, deliver bool) {
	deliver = !(i.m.MinTTL > 0 && ttl > 0 && ttl < i.m.MinTTL)
	if i.decided {
		return i.v, deliver && !i.v.Blocked()
	}
	i.observe(seg)
	return i.evaluate(), deliver
}

// ClientOOB feeds an out-of-band (MSG_OOB) byte. The middlebox sees it inline —
// that is the entire mechanism of the oob emitter, and why §3 measures oob-at-1
// through 3/3 — while the receiving TCP strips it, so it is never delivered.
func (i *Inspector) ClientOOB(b []byte) Verdict {
	if i.decided {
		return i.v
	}
	i.oob = true
	i.observe(b)
	return i.evaluate()
}

// observe adds bytes to the inspection window, honouring InspectBytes.
func (i *Inspector) observe(seg []byte) {
	room := len(seg)
	if i.m.InspectBytes > 0 {
		room = min(room, max(0, i.m.InspectBytes-i.fed))
	}
	i.fed += len(seg)
	if i.m.ReassembleTCP {
		i.buf = append(i.buf, seg[:room]...)
		return
	}
	// Without reassembly each segment is judged alone: the middlebox has no
	// memory across segment boundaries, which is the property every
	// hostname-splitting TCP emitter relies on.
	i.buf = append(i.buf[:0], seg[:room]...)
}

// evaluate runs the model's predicates against the current window. It returns
// the zero Verdict while the evidence is still incomplete, so the caller keeps
// forwarding and keeps feeding.
func (i *Inspector) evaluate() Verdict {
	if i.m.RejectOOB && i.oob {
		return i.decide(Verdict{
			Action: i.m.action(),
			Reason: "endpoint is broken by an out-of-band byte in the stream",
		})
	}
	if !i.m.RecordAware {
		return i.evaluateRaw()
	}
	return i.evaluateRecords()
}

// evaluateRaw is the naive model: scan the reassembled bytes for a blocked
// hostname with no notion of TLS framing.
func (i *Inspector) evaluateRaw() Verdict {
	hay := strings.ToLower(string(i.buf))
	for _, b := range i.m.Blocked {
		b = strings.ToLower(strings.TrimSuffix(b, "."))
		if b != "" && strings.Contains(hay, b) {
			i.name = b
			return i.decide(Verdict{
				Action: i.m.action(), Match: b,
				Reason: "hostname found in the raw byte stream",
			})
		}
	}
	if i.exhausted() {
		return i.decide(Verdict{Reason: "inspection window exhausted, no hostname seen"})
	}
	return Verdict{}
}

// evaluateRecords is the record-aware model, and the measured one.
//
// tlsmsg.Parse walks only the first record's body, which is exactly the Türk
// Telekom rule: the SNI is found if and only if the hostname is complete inside
// record 1 (MEASUREMENTS.md §3.2). When FirstRecordOnly is false the middlebox
// is stronger — it reassembles every complete record before parsing — and a
// record split no longer helps.
func (i *Inspector) evaluateRecords() Verdict {
	view := i.buf
	if !i.m.FirstRecordOnly {
		if joined, ok := joinRecords(i.buf); ok {
			view = joined
		}
	}
	m := tlsmsg.Parse(view, i.port)
	if m.Proto != tlsmsg.ProtoTLS {
		if i.exhausted() {
			return i.decide(Verdict{Reason: "inspection window exhausted, not TLS"})
		}
		return Verdict{}
	}
	if m.ServerName != "" {
		i.name = m.ServerName
	}
	if b, ok := i.m.blocks(m.ServerName); ok && m.HasSNI() {
		return i.decide(Verdict{
			Action: i.m.action(), Match: b,
			Reason: "SNI hostname is complete inside the parsed record",
		})
	}
	// A decision cannot be taken before the record the model parses is whole:
	// the hostname may still be arriving.
	if !m.Complete {
		if i.exhausted() {
			return i.decide(Verdict{Reason: "inspection window exhausted mid-record"})
		}
		return Verdict{}
	}
	// A reassembling model must also wait for the whole handshake MESSAGE. Its
	// first record being complete proves nothing when the hello was split: an
	// early "no blocked hostname" here would let every reframing emitter defeat
	// a model whose entire point is that reframing does not help.
	if !i.m.FirstRecordOnly && !handshakeComplete(view) {
		if i.exhausted() {
			return i.decide(Verdict{Reason: "inspection window exhausted mid-handshake"})
		}
		return Verdict{}
	}
	if i.m.RejectSpanningRecords {
		// Deliberately the raw buffer, never the joined view: the whole question
		// is how the client FRAMED the handshake, which joining erases.
		if spans, ok := handshakeSpansRecords(i.buf); ok && spans {
			return i.decide(Verdict{
				Action: i.m.action(), Match: i.name,
				Reason: "handshake message spans more than one TLS record",
			})
		}
	}
	return i.decide(Verdict{Reason: "no blocked hostname in the parsed record"})
}

func (i *Inspector) exhausted() bool {
	return i.m.InspectBytes > 0 && i.fed >= i.m.InspectBytes
}

// joinRecords concatenates the bodies of every complete record in b into a
// single synthetic record. ok is false if the first record is not yet whole,
// because there is nothing meaningful to parse.
func joinRecords(b []byte) ([]byte, bool) {
	var body []byte
	var hdr tlsmsg.Header
	first := true
	for len(b) >= 5 {
		h, ok := tlsmsg.ParseHeader(b)
		if !ok || len(b) < 5+h.Length {
			break
		}
		if first {
			hdr, first = h, false
		}
		body = append(body, b[5:5+h.Length]...)
		b = b[5+h.Length:]
	}
	if first {
		return nil, false
	}
	hdr.Length = len(body)
	out := hdr.Bytes()
	return append(out[:], body...), true
}

// handshakeSpansRecords reports whether the first handshake message is longer
// than the first record that carries it. ok is false while the answer is still
// unknowable, which is not the same as "no".
func handshakeSpansRecords(b []byte) (spans, ok bool) {
	h, got := tlsmsg.ParseHeader(b)
	if !got || len(b) < 5+h.Length {
		return false, false // the first record has not arrived in full
	}
	if h.Length < 4 {
		// The 4-byte handshake header does not even fit in record 1. A second
		// record proves the message continues; without one there is nothing to
		// judge yet.
		more := len(b) > 5+h.Length
		return more, more
	}
	msgLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	return 4+msgLen > h.Length, true
}

// handshakeComplete reports whether view — a single record, real or joined —
// carries the whole of its first handshake message.
func handshakeComplete(view []byte) bool {
	h, ok := tlsmsg.ParseHeader(view)
	if !ok || h.Length < 4 || len(view) < 5+h.Length {
		return false
	}
	msgLen := int(view[6])<<16 | int(view[7])<<8 | int(view[8])
	return h.Length >= 4+msgLen
}
