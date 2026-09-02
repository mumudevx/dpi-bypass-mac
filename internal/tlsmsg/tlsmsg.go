// Package tlsmsg parses the first application message a client sends on a
// connection: a TLS ClientHello, a plaintext HTTP request head, or a QUIC
// Initial.
//
// It is pure — no net, no os, no time — because the measured DPI rule this whole
// tool is built on is a statement about byte offsets, and a statement about byte
// offsets must be checkable by a unit test rather than by a network experiment.
// MEASUREMENTS.md §3.3 records that the code path expressing that rule sat at 0%
// coverage in the previous implementation precisely because it was welded to a
// socket.
package tlsmsg

import (
	"encoding/binary"
	"errors"

	"github.com/mumudevx/dpi-bypass-mac/internal/httpmsg"
)

type Proto uint8

const (
	ProtoUnknown Proto = iota
	ProtoTLS
	ProtoHTTP
	ProtoQUICInitial
)

var protoNames = [...]string{"unknown", "tls", "http", "quic"}

func (p Proto) String() string {
	if int(p) >= len(protoNames) {
		return protoNames[ProtoUnknown]
	}
	return protoNames[p]
}

// ErrNoSNI is returned by callers that require a server name and did not get
// one. Parse itself never fails: an unparseable buffer is ProtoUnknown.
var ErrNoSNI = errors.New("tlsmsg: first message carries no server name")

const (
	recHdrLen        = 5
	recTypeHandshake = 0x16
)

// Meta is the parse of a client's first application message.
//
// For ProtoTLS, SNIStart/SNIEnd are offsets into the FIRST TLS record's BODY
// (relative to payload[BodyOff:]), because the measured DPI rule is expressed in
// record-body coordinates. For ProtoHTTP they are unused and HostStart/HostEnd
// are absolute offsets into the payload.
type Meta struct {
	Proto      Proto
	DstPort    int
	Complete   bool // the declared first message is fully buffered
	Truncated  bool // a deadline or size cap was hit first
	ServerName string

	RecHdr  [5]byte // the original record header, reused by reframers
	BodyOff int     // absolute offset of the first record's body (5 for TLS)
	BodyLen int     // declared length of the first record's body

	SNIStart int // body-relative; -1 when absent
	SNIEnd   int // body-relative, exclusive

	HostStart int // payload-absolute; -1 when absent
	HostEnd   int
	HeaderEnd int // end of the HTTP header block; -1 otherwise
}

func (m Meta) HasSNI() bool { return m.SNIStart >= 0 && m.SNIEnd > m.SNIStart }

// HasHost reports whether an HTTP Host header value was located.
func (m Meta) HasHost() bool { return m.HostStart >= 0 && m.HostEnd > m.HostStart }

// RecordEnd is the absolute offset just past the first TLS record.
func (m Meta) RecordEnd() int { return m.BodyOff + m.BodyLen }

// MaxFirstRecordEnd is the largest body offset at which the first TLS record may
// end while still hiding the hostname from the DPI.
//
// Measured 2026-09-02, Türk Telekom AS9121, 66 shuffled trials, both records in
// ONE TCP segment (MEASUREMENTS.md §3.2): every first-record end at sniEnd-1 or
// below passes 3/3 on discord.com and discord.gg; sniEnd, sniEnd+1, sniEnd+20 and
// sniEnd+200 are blocked 0/3. The same predicate explains §3's periodic results:
// tlsrec-every-16 and -every-64 pass (first record ends at 16 and 64, both <=
// sniEnd-1 = 121) while tlsrec-every-256 fails (256 > 121). One rule, 14 points.
func (m Meta) MaxFirstRecordEnd() (int, bool) {
	if !m.HasSNI() {
		return 0, false
	}
	return m.SNIEnd - 1, true
}

// Classify names the protocol of a buffer that may still be a prefix. It is
// deliberately prefix-tolerant: the caller decides how long to keep reading
// based on this answer, and a premature "unknown" stalls the connection until a
// deadline instead of assembling the message.
func Classify(b []byte, dstPort int) Proto {
	switch {
	case looksTLSHandshake(b):
		return ProtoTLS
	case isQUICInitial(b):
		return ProtoQUICInitial
	case httpmsg.Detect(b):
		return ProtoHTTP
	}
	return ProtoUnknown
}

// looksTLSHandshake accepts any prefix consistent with a TLS handshake record
// header: type 0x16 and a legacy record version of 0x03xx, xx <= 4.
func looksTLSHandshake(b []byte) bool {
	if len(b) == 0 || b[0] != recTypeHandshake {
		return false
	}
	if len(b) >= 2 && b[1] != 0x03 {
		return false
	}
	if len(b) >= 3 && b[2] > 0x04 {
		return false
	}
	return true
}

// Need reports how many more bytes are required before the first application
// message is complete. ok=false means the shape is unrecognisable and the caller
// must stop waiting rather than silently operating on a prefix.
//
// This is the guard for the defect MEASUREMENTS.md §3.5 names: a single un-looped
// Read of a 1502-byte post-quantum ClientHello returns the first segment, and
// planning a record split against a prefix silently degrades it into a one-byte
// TCP split, which measures 0/5.
func Need(b []byte, p Proto) (want int, ok bool) {
	switch p {
	case ProtoTLS:
		if !looksTLSHandshake(b) {
			return 0, false
		}
		if len(b) < recHdrLen {
			return recHdrLen - len(b), true
		}
		total := recHdrLen + int(binary.BigEndian.Uint16(b[3:recHdrLen]))
		if len(b) >= total {
			return 0, true
		}
		return total - len(b), true
	case ProtoHTTP:
		return httpmsg.Need(b)
	case ProtoQUICInitial:
		// UDP delivers whole datagrams; there is nothing further to wait for.
		if !isQUICInitial(b) {
			return 0, false
		}
		return 0, true
	}
	return 0, false
}

// Parse never fails. An unrecognisable buffer yields Proto ProtoUnknown with
// every offset at -1, so a caller that forgets to check the protocol still can
// not index into the payload with a bogus offset.
//
// Truncated is left false: only the reader knows whether it stopped because the
// message ended or because a deadline or size cap fired, so flow.ReadFirstMessage
// sets it.
func Parse(b []byte, dstPort int) Meta {
	m := Meta{
		DstPort:   dstPort,
		SNIStart:  -1,
		SNIEnd:    -1,
		HostStart: -1,
		HostEnd:   -1,
		HeaderEnd: -1,
	}
	m.Proto = Classify(b, dstPort)
	switch m.Proto {
	case ProtoTLS:
		parseTLS(b, &m)
	case ProtoHTTP:
		parseHTTP(b, &m)
	case ProtoQUICInitial:
		m.Complete = true
	}
	return m
}

func parseTLS(b []byte, m *Meta) {
	if len(b) < recHdrLen {
		return // header not buffered yet: BodyLen unknown, Complete false
	}
	copy(m.RecHdr[:], b[:recHdrLen])
	m.BodyOff = recHdrLen
	m.BodyLen = int(binary.BigEndian.Uint16(b[3:recHdrLen]))
	end := recHdrLen + m.BodyLen
	m.Complete = len(b) >= end
	if end > len(b) {
		end = len(b)
	}
	// The SNI is walked against whatever is buffered, so a caller that must name
	// a flow before the record completes still can. Every offset returned is
	// inside the walked slice, so SNIEnd <= min(BodyLen, len(b)-BodyOff) always.
	name, start, stop := parseClientHelloSNI(b[recHdrLen:end])
	if start >= 0 {
		m.ServerName, m.SNIStart, m.SNIEnd = name, start, stop
	}
}

func parseHTTP(b []byte, m *Meta) {
	r, err := httpmsg.Parse(b)
	if err != nil {
		return
	}
	m.Complete = r.Complete
	m.HeaderEnd = r.HeaderEnd
	if r.HasHost() {
		m.HostStart, m.HostEnd = r.HostStart, r.HostEnd
		m.ServerName = r.Host
	}
}
