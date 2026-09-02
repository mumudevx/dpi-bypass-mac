// Package strategy turns a bypass strategy written as text into a Plan: a pure
// value naming exactly which bytes leave the socket, in what order, with which
// socket options.
//
// Nothing here does I/O. That is deliberate. MEASUREMENTS.md §3.3 records that
// the one code path expressing the measured DPI rule sat at 0% coverage in the
// previous implementation because it was welded to a socket, and §3.5 records
// the consequence: its frag_window knob was inert and it never verified that the
// record cut landed before sniEnd. Here a strategy is a value, the rule is a
// typed error, and both are checkable by a unit test.
//
// A spec is also a wire format in its own right: the prober serialises it, the
// verdict store caches it, `dpb apply` imports one a stranger pasted in a forum.
// So Parse(String(s)) round-trips exactly and canonicalisation is idempotent —
// instability there silently corrupts every measurement built on top of it.
package strategy

import (
	"fmt"
	"strings"
)

// Cap is a bitset of transport capabilities. An op declares what it needs, a
// Transport declares what it has, and the mismatch is reported by name before a
// byte moves — the categorical fix for a profile that demands root and then
// silently ships the SNI unfragmented.
type Cap uint32

const (
	CapStreamWrite Cap = 1 << iota
	CapNoDelay
	CapSockTTL
	CapOOB
	CapUDPTTL
	CapRawInject
	CapRawSeq // never granted in v1; see emit.Transport.SeqState
	// CapDatagram means one write is one packet: the transport preserves
	// message boundaries, so a segment that is not part of the payload can be
	// sent as an ordinary write without corrupting anything. Only a connected
	// datagram socket grants it, which is what keeps the UDP decoy family
	// (SegFakeDatagram) off a TCP transport.
	CapDatagram
)

var capNames = []struct {
	c Cap
	n string
}{
	{CapStreamWrite, "streamwrite"},
	{CapNoDelay, "nodelay"},
	{CapSockTTL, "sockttl"},
	{CapOOB, "oob"},
	{CapUDPTTL, "udpttl"},
	{CapRawInject, "rawinject"},
	{CapRawSeq, "rawseq"},
	{CapDatagram, "datagram"},
}

// Has reports whether c provides every bit in want. Note that Has(0) is true:
// a strategy that needs nothing is satisfied by any transport.
func (c Cap) Has(want Cap) bool { return c&want == want }

// Missing returns the bits of want that c does not provide, so an error can
// name the actual shortfall rather than printing both bitsets and leaving the
// subtraction to the reader.
func (c Cap) Missing(want Cap) Cap { return want &^ c }

func (c Cap) String() string {
	if c == 0 {
		return "none"
	}
	var (
		parts []string
		known Cap
	)
	for _, e := range capNames {
		if c&e.c != 0 {
			parts = append(parts, e.n)
			known |= e.c
		}
	}
	if rest := c &^ known; rest != 0 {
		parts = append(parts, fmt.Sprintf("unknown(%#x)", uint32(rest)))
	}
	return strings.Join(parts, "|")
}
