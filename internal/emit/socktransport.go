package emit

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/mumudevx/dpb/internal/strategy"
)

// SockTransport is an ordinary bound kernel socket, used unchanged by both the
// proxy front-end and the TUN front-end.
//
// It is not safe for concurrent use by multiple goroutines, and it does not need
// to be: a plan is emitted by exactly one goroutine, before the relay starts.
type SockTransport struct {
	c   *net.TCPConn
	rc  syscall.RawConn
	inj RawInjector

	caps   strategy.Cap
	v6     bool
	defTTL int

	local  netip.AddrPort
	remote netip.AddrPort
}

var _ Transport = (*SockTransport)(nil)

// NewSockTransport wraps an established TCP connection.
//
// Capabilities are decided here, once, from what the socket actually granted —
// never from what the platform is assumed to support. In particular CapSockTTL
// is withheld unless the kernel's default hop limit could be read, because a
// per-segment TTL that cannot be restored afterwards would black-hole the rest
// of the connection. When it is withheld, grantHopLimit says so on stderr: a
// capability that disappears silently is a strategy downgraded without anyone
// noticing.
//
// inj may be nil; it is not closed by Close, because a raw-injection socket is a
// process-wide resource shared by every transport.
func NewSockTransport(c *net.TCPConn, inj RawInjector) (*SockTransport, error) {
	if c == nil {
		return nil, fmt.Errorf("emit: new sock transport: nil connection")
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("emit: new sock transport: raw conn: %w", err)
	}

	t := &SockTransport{
		c:      c,
		rc:     rc,
		inj:    inj,
		caps:   strategy.CapStreamWrite,
		local:  toAddrPort(c.LocalAddr()),
		remote: toAddrPort(c.RemoteAddr()),
	}
	// The socket family, not the peer's notional family: an AF_INET6 socket
	// carrying a v4-mapped peer takes IPV6_UNICAST_HOPS, not IP_TTL.
	t.v6 = t.local.IsValid() && !t.local.Addr().Is4()

	// Every multi-write plan is a lie without this: with Nagle on, the kernel
	// coalesces the segments back into one and the "split" never reaches the wire.
	if err := c.SetNoDelay(true); err != nil {
		return nil, fmt.Errorf("emit: new sock transport: %s: TCP_NODELAY: %w", t.remote, err)
	}
	t.caps |= strategy.CapNoDelay

	if ttl, granted := grantHopLimit(t.v6); granted != 0 {
		t.defTTL = ttl
		t.caps |= granted
	}
	t.caps |= oobCaps
	if inj != nil {
		t.caps |= strategy.CapRawInject
	}
	return t, nil
}

func (t *SockTransport) Caps() strategy.Cap { return t.caps }

func (t *SockTransport) Write(b []byte) (int, error) { return t.c.Write(b) }

// WriteOOB sends b as TCP urgent data. b must be exactly one byte: MSG_OOB marks
// only the LAST byte of the write as urgent, so a multi-byte OOB write would
// deliver the leading bytes in band and corrupt the stream the plan promised to
// preserve.
func (t *SockTransport) WriteOOB(b []byte) (int, error) {
	if !t.caps.Has(strategy.CapOOB) {
		return 0, fmt.Errorf("%w: %s on %s", ErrCapUnavailable, strategy.CapOOB, t.remote)
	}
	if len(b) != 1 {
		return 0, fmt.Errorf("emit: WriteOOB wants exactly 1 urgent byte, got %d: "+
			"MSG_OOB marks only the final byte, so the rest would go in band", len(b))
	}
	n, err := sendOOB(t.rc, b)
	if err != nil {
		return n, fmt.Errorf("emit: MSG_OOB to %s: %w", t.remote, err)
	}
	return n, nil
}

func (t *SockTransport) SetTTL(ttl int) error {
	if !t.caps.Has(strategy.CapSockTTL) {
		return fmt.Errorf("%w: %s on %s", ErrCapUnavailable, strategy.CapSockTTL, t.remote)
	}
	if ttl < 1 || ttl > 255 {
		return fmt.Errorf("emit: hop limit %d out of range 1..255", ttl)
	}
	return setHopLimit(t.rc, t.v6, ttl)
}

// ResetTTL restores the kernel default read at construction — never a hardcoded
// 64 (DOSSIER §3, and net.inet.ip.ttl is a tunable a user may well have changed).
func (t *SockTransport) ResetTTL() error {
	if !t.caps.Has(strategy.CapSockTTL) {
		return fmt.Errorf("%w: %s on %s", ErrCapUnavailable, strategy.CapSockTTL, t.remote)
	}
	return setHopLimit(t.rc, t.v6, t.defTTL)
}

// ttl reads the hop limit back off the socket. It exists so a test can verify
// through getsockopt what setsockopt claimed to do, rather than trusting the
// setter's own return value.
func (t *SockTransport) ttl() (int, error) { return getHopLimit(t.rc, t.v6) }

func (t *SockTransport) InjectRaw(pkt []byte) error {
	if t.inj == nil {
		return fmt.Errorf("%w: %s on %s", ErrCapUnavailable, strategy.CapRawInject, t.remote)
	}
	if err := t.inj.Inject(pkt); err != nil {
		return fmt.Errorf("emit: inject %d raw bytes toward %s: %w", len(pkt), t.remote, err)
	}
	return nil
}

// SeqState always reports ok=false. struct tcp_connection_info in the macOS 26
// SDK's netinet/tcp.h carries no snd_nxt field, so a kernel socket cannot tell us
// its own sequence space, so CapRawSeq is never granted and every seqovl /
// fakedsplit op is rejected at validation with a cited reason instead of putting
// decoys 4 GB out of window (DOSSIER §4).
func (t *SockTransport) SeqState() (SeqState, bool) { return SeqState{}, false }

func (t *SockTransport) Local() netip.AddrPort  { return t.local }
func (t *SockTransport) Remote() netip.AddrPort { return t.remote }

func (t *SockTransport) Close() error { return t.c.Close() }

// Conn exposes the underlying connection so the front-end can relay on it after
// the plan has been emitted. The transport does not take ownership of the read
// side at any point.
func (t *SockTransport) Conn() *net.TCPConn { return t.c }

func toAddrPort(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	case *net.UDPAddr:
		return v.AddrPort()
	case nil:
		return netip.AddrPort{}
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}
		}
		return ap
	}
}
