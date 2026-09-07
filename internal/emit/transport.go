// Package emit is the only impure code in the desync path.
//
// internal/strategy turns a spec into a Plan — a pure value naming exactly which
// bytes leave the socket, in what order, with which socket options. This package
// executes that value against a real file descriptor and nothing else. The split
// exists because MEASUREMENTS.md §3.3 records that the previous implementation's
// one expression of the measured DPI rule sat at 0% coverage precisely because it
// was welded to a socket.
//
// Both front-ends dial an ordinary bound kernel socket and wrap it in the same
// SockTransport. There is deliberately no second Transport implementation for TUN
// mode: two emitters cannot drift apart if there is only one.
package emit

import (
	"errors"
	"net/netip"

	"github.com/mumudevx/dpb/internal/strategy"
)

// ErrCapUnavailable is returned when a plan asks a transport for something the
// transport does not have. It is always accompanied by the missing capability
// names, because "desync failed" without a mechanical reason is how a profile
// ends up demanding root and then silently shipping the SNI unfragmented.
var ErrCapUnavailable = errors.New("emit: transport lacks a required capability")

// ErrShortWrite means the transport accepted fewer bytes than the segment
// carried. A Transport that does this has torn the stream, so the sender stops
// rather than continuing with the next segment.
var ErrShortWrite = errors.New("emit: transport accepted a partial segment")

// SeqState is the upstream TCP sequence space. See Transport.SeqState for why it
// is never populated in v1.
type SeqState struct {
	ISN      uint32
	SndNxt   uint32
	RcvNxt   uint32
	WindowOK bool
}

// Transport is the seam between the emitter set and an interception mode. Proxy
// mode and TUN mode both dial an ordinary bound kernel socket and wrap it in the
// SAME SockTransport, so the two front-ends cannot drift apart.
type Transport interface {
	Caps() strategy.Cap
	Write(b []byte) (int, error)
	WriteOOB(b []byte) (int, error)
	SetTTL(ttl int) error
	ResetTTL() error
	InjectRaw(pkt []byte) error
	// SeqState reports the upstream sequence space. ok is ALWAYS false for a
	// kernel socket on Darwin: struct tcp_connection_info in netinet/tcp.h has no
	// snd_nxt field (verified against the macOS 26 SDK, 0 matches), so CapRawSeq
	// can never be granted and every seqovl/fakedsplit op fails validation with a
	// mechanical reason instead of emitting decoys out of window. It lights up
	// unchanged the day a netstack-owned endpoint exists.
	SeqState() (SeqState, bool)
	Local() netip.AddrPort
	Remote() netip.AddrPort
	Close() error
}

// RawInjector writes a fully-formed IP packet. Nothing in v1 supplies one: the
// fake-packet family is registered and rejected because SeqState is unavailable,
// so a decoy would land 4 GB out of window. The seam is here so the day a
// netstack-owned endpoint exists, only the constructor changes.
type RawInjector interface {
	Inject(pkt []byte) error
	Close() error
}

// Governor is a process-wide token bucket over small writes. The XNU
// `assertion failed: ifp->if_sndbyte_unsent >= 0` panic is a pre-existing Apple
// defect (public reports back to xnu-4570, 2017; DOSSIER GT13) provoked by high
// VOLUME of small writes, so the guard must be process-wide, not per-connection.
// It COALESCES adjacent small segments when short rather than blocking a write.
//
// Blocking would be the wrong shape twice over: it would add unbounded latency to
// a censorship-circumvention path, and it would not actually reduce the total
// number of small writes the machine performs — only delay them.
type Governor interface {
	// Reserve asks to perform n writes for one plan and returns how many are
	// permitted. The result is always in [1, n] for n >= 1: a plan that has bytes
	// to send must always be able to send them, and the caller coalesces the
	// remainder into the writes it was granted. Reserve never blocks.
	Reserve(n int) int
	Stats() GovernorStats
}

// GovernorStats counts writes, not plans. Granted is how many writes the
// governor permitted; Coalesced is how many writes were folded into a neighbour
// because the bucket was short.
type GovernorStats struct {
	Granted   uint64
	Coalesced uint64
}
