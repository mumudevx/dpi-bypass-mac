package resolve

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ErrTCPForbidden is returned if any code path attempts plaintext DNS over TCP.
//
// TCP/53 is RST-filtered at EVERY port on Türk Telekom (MEASUREMENTS.md §2:
// both `dig +tcp @8.8.8.8 discord.com` and `dig +tcp -p 1253 @77.88.8.8
// discord.com` are connection-reset), so a truncation fallback to TCP breaks
// for exactly the names that matter. It is not a configurable preference: this
// package exposes no constructor and no dial helper that can produce a
// plaintext TCP DNS connection, and this error exists so a caller that reaches
// for one gets a citation instead of a socket.
var ErrTCPForbidden = errors.New("resolve: DNS over TCP is never attempted")

// udpNetwork is the only network name plaintext DNS is ever dialled on. It is a
// constant, not a parameter, because a parameter is a place a config key can
// eventually reach.
const udpNetwork = "udp"

// ForbidTCP reports ErrTCPForbidden for any network that is not a datagram
// network. Configuration and CLI layers call it so "allow_tcp53 = true" fails
// loudly at parse time with the measurement attached, rather than quietly
// producing a resolver that cannot work here.
func ForbidTCP(network string) error {
	switch network {
	case "udp", "udp4", "udp6":
		return nil
	default:
		return fmt.Errorf("%w (network %q; MEASUREMENTS.md §2)", ErrTCPForbidden, network)
	}
}

// udpReadMax bounds a single datagram read. 4096 covers any EDNS0 buffer size
// a sane resolver advertises; anything larger sets TC and the chain re-asks an
// encrypted resolver instead of falling back to TCP.
const udpReadMax = 4096

// udpDeadline is the fallback per-exchange deadline when the caller's context
// carries none. The chain always sets one; a standalone caller should not hang.
const udpDeadline = 5 * time.Second

type udpResolver struct {
	label     string
	transport string
	addr      netip.AddrPort
	d         *net.Dialer
}

// NewUDP builds a plaintext UDP resolver.
//
// addr must be an IP literal with a port. A hostname is rejected rather than
// resolved: resolving it is precisely the fall-through to the system resolver
// that MEASUREMENTS.md §5.4 records as the bug that invalidated an entire
// measurement run.
func NewUDP(label, addr string, d *net.Dialer) (Resolver, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("resolve: UDP resolver %q address %q must be a literal ip:port, "+
			"never a hostname (MEASUREMENTS.md §5.4): %w", label, addr, err)
	}
	if ap.Port() == 0 {
		return nil, fmt.Errorf("resolve: UDP resolver %q has port 0", label)
	}
	if label == "" {
		label = "udp-" + ap.String()
	}
	if d == nil {
		d = &net.Dialer{}
	}
	// The transport label distinguishes the measured alt-port fallback from
	// port 53, which MEASUREMENTS.md §2 shows is per-QNAME dropped here.
	transport := "udp-alt"
	if ap.Port() == 53 {
		transport = "udp"
	}
	return &udpResolver{label: label, transport: transport, addr: ap, d: d}, nil
}

func (r *udpResolver) Label() string     { return r.label }
func (r *udpResolver) Transport() string { return r.transport }

func (r *udpResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if err := ForbidTCP(udpNetwork); err != nil {
		return nil, err
	}
	if len(query) < headerLen {
		return nil, ErrShortMessage
	}
	callerID := binary.BigEndian.Uint16(query[0:2])

	out := make([]byte, len(query))
	copy(out, query)
	// A random ID on the wire is the only anti-spoofing this transport has.
	// The caller's ID is restored on the way back so the funnel is invisible.
	wireID, err := randomID()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(out[0:2], wireID)

	conn, err := r.d.DialContext(ctx, udpNetwork, r.addr.String())
	if err != nil {
		return nil, fmt.Errorf("resolve: %s: dial %s: %w", r.label, r.addr, err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(udpDeadline)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("resolve: %s: set deadline: %w", r.label, err)
	}
	if _, err := conn.Write(out); err != nil {
		return nil, fmt.Errorf("resolve: %s: write query: %w", r.label, err)
	}

	buf := make([]byte, udpReadMax)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("resolve: %s: read answer for %s: %w",
				r.label, questionLabel(query), err)
		}
		resp := buf[:n]
		if n < headerLen || !IsResponse(resp) {
			continue
		}
		if binary.BigEndian.Uint16(resp[0:2]) != wireID || !SameQuestion(out, resp) {
			// An answer to a different question or a different ID on a
			// connected socket is either a stale datagram or a spoof. Keep
			// reading until the deadline rather than accepting it.
			continue
		}
		answer := make([]byte, n)
		copy(answer, resp)
		binary.BigEndian.PutUint16(answer[0:2], callerID)
		return answer, nil
	}
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("resolve: random transaction ID: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// questionLabel is for error messages only; an unparseable question is still
// worth reporting as an exchange failure.
func questionLabel(msg []byte) string {
	q, err := FirstQuestion(msg)
	if err != nil {
		return "<unparseable question>"
	}
	return q.String()
}
