package emit

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/mumudevx/dpb/internal/strategy"
)

// UDPTransport is a CONNECTED UDP socket, used by quicfake: set a low hop limit,
// send N crafted QUIC Initials that expire before the origin, restore the hop
// limit, send the real datagram.
//
// One Segment is one datagram. That is the whole reason this is a separate
// transport rather than a *net.UDPConn behind SockTransport: on a datagram socket
// the segment boundaries the plan describes are the packet boundaries on the
// wire, and merging two of them would change what the peer receives, not just
// how it arrives.
type UDPTransport struct {
	c  *net.UDPConn
	rc syscall.RawConn

	caps   strategy.Cap
	v6     bool
	defTTL int

	local  netip.AddrPort
	remote netip.AddrPort
}

var _ Transport = (*UDPTransport)(nil)

// UDPCaps is what a connected kernel UDP socket on this machine grants,
// computed the way NewUDPTransport computes it.
//
// It exists so a front end can refuse a UDP strategy its transport cannot
// satisfy at CONFIGURATION time, with the shortfall named, instead of
// discovering it per datagram on an already-open socket. The TTL bits depend on
// a sysctl read, so this is a measurement of this machine, not a constant.
func UDPCaps(v6 bool) strategy.Cap {
	caps := strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapDatagram
	if ttl, err := defaultHopLimit(v6); err == nil && ttl > 0 {
		caps |= sockTTLCaps
	}
	return caps
}

// NewUDPTransport wraps a connected UDP socket. The socket MUST be connected
// (dialled, not listening): an unconnected socket has no remote address, so
// Write has nowhere to send and the plan would fail per datagram instead of once
// at construction.
func NewUDPTransport(c *net.UDPConn) (*UDPTransport, error) {
	if c == nil {
		return nil, fmt.Errorf("emit: new udp transport: nil connection")
	}
	remote := toAddrPort(c.RemoteAddr())
	if !remote.IsValid() {
		return nil, fmt.Errorf("emit: new udp transport: socket is not connected")
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("emit: new udp transport: raw conn: %w", err)
	}

	t := &UDPTransport{
		c:  c,
		rc: rc,
		// CapNoDelay is granted unconditionally and truthfully: Nagle is a TCP
		// mechanism, so a datagram socket can never coalesce two segments. A plan
		// with more than one segment asks for CapNoDelay (strategy.Plan.Caps), and
		// refusing it here would reject every quicfake plan for a property UDP has
		// by construction.
		//
		// CapDatagram is the same kind of truth about message boundaries: one
		// write is one packet here, so a decoy segment can be sent without
		// corrupting the payload. It is the capability a SegFakeDatagram plan
		// asks for, and no stream transport grants it.
		caps:   strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapDatagram,
		local:  toAddrPort(c.LocalAddr()),
		remote: remote,
	}
	t.v6 = t.local.IsValid() && !t.local.Addr().Is4()

	if ttl, err := defaultHopLimit(t.v6); err == nil && ttl > 0 {
		t.defTTL = ttl
		// Both bits: the op declares CapUDPTTL, but strategy.Plan.Caps derives
		// CapSockTTL from any segment carrying a TTL, so a transport that can do
		// one must advertise the other or no TTL plan will ever validate.
		t.caps |= sockTTLCaps
	}
	return t, nil
}

func (t *UDPTransport) Caps() strategy.Cap { return t.caps }

func (t *UDPTransport) Write(b []byte) (int, error) { return t.c.Write(b) }

// WriteOOB is meaningless on UDP: there is no urgent pointer outside TCP.
func (t *UDPTransport) WriteOOB([]byte) (int, error) {
	return 0, fmt.Errorf("%w: %s has no meaning on a datagram socket to %s",
		ErrCapUnavailable, strategy.CapOOB, t.remote)
}

func (t *UDPTransport) SetTTL(ttl int) error {
	if !t.caps.Has(strategy.CapUDPTTL) {
		return fmt.Errorf("%w: %s on %s", ErrCapUnavailable, strategy.CapUDPTTL, t.remote)
	}
	if ttl < 1 || ttl > 255 {
		return fmt.Errorf("emit: hop limit %d out of range 1..255", ttl)
	}
	return setHopLimit(t.rc, t.v6, ttl)
}

func (t *UDPTransport) ResetTTL() error {
	if !t.caps.Has(strategy.CapUDPTTL) {
		return fmt.Errorf("%w: %s on %s", ErrCapUnavailable, strategy.CapUDPTTL, t.remote)
	}
	return setHopLimit(t.rc, t.v6, t.defTTL)
}

func (t *UDPTransport) ttl() (int, error) { return getHopLimit(t.rc, t.v6) }

// InjectRaw is never available on this transport. The UDP fake path is
// unprivileged by design — only TCP fakes need a raw socket, and those are
// compiled out on Darwin because SeqState is unavailable.
func (t *UDPTransport) InjectRaw([]byte) error {
	return fmt.Errorf("%w: %s on a datagram socket to %s",
		ErrCapUnavailable, strategy.CapRawInject, t.remote)
}

func (t *UDPTransport) SeqState() (SeqState, bool) { return SeqState{}, false }

func (t *UDPTransport) Local() netip.AddrPort  { return t.local }
func (t *UDPTransport) Remote() netip.AddrPort { return t.remote }

func (t *UDPTransport) Close() error { return t.c.Close() }

// Conn exposes the underlying socket so the caller can relay datagrams on it
// after the fakes have gone out.
func (t *UDPTransport) Conn() *net.UDPConn { return t.c }
