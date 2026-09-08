package flow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// The datagram half of the datapath, shared by both front ends.
//
// It lives here for the same reason the stream half does: TUN mode and SOCKS5
// UDP ASSOCIATE must not grow two UDP emitters that can drift apart. There is
// deliberately no ladder on this path. A datagram flow has no handshake and no
// reset to classify, so there is no evidence to escalate on — a UDP strategy is
// applied once, to the first datagram, or not at all, and the shipped default
// is to apply none (see the QUIC policy in the front ends).

// ErrNotDatagram means the connection handed to the datagram emitter is not a
// connected UDP socket, so segment boundaries would not be packet boundaries.
// It is an error rather than a silent fallback to one write: a decoy merged
// into the payload is corruption, not a weaker strategy.
var ErrNotDatagram = errors.New("flow: not a connected UDP socket")

// DefaultUDPDialTimeout bounds one datagram-socket connect. A connected UDP
// socket does no handshake, so this only bounds the route lookup and the bind.
const DefaultUDPDialTimeout = 2 * time.Second

// UDPDialer opens the upstream socket for one datagram flow.
//
// It is separate from Dialer because this path never resolves anything: the
// destination is already an address, taken off a captured packet or out of a
// SOCKS5 request, and MEASUREMENTS.md §5.4 is the reason a name must never
// reach a dial. There is no Target here at all, so there is nothing to resolve.
type UDPDialer interface {
	DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

// NetUDPDialer is the shipped UDPDialer: an ordinary kernel UDP socket,
// connected to dst and optionally pinned to the uplink interface.
//
// The pin is what keeps our own datagrams off the tunnel in TUN mode: the
// capture routes cover the whole address space, so an unbound socket would be
// routed back into our own netstack and loop. IP_BOUND_IF selects the scope and
// the interface-scoped default route supplies the gateway, exactly as for TCP.
type NetUDPDialer struct {
	// Interface pins the socket by name (IP_BOUND_IF / IPV6_BOUND_IF). Empty
	// leaves the socket on the system's routing decision, which is correct for
	// proxy mode.
	Interface string
	// Timeout bounds the connect. Zero means DefaultUDPDialTimeout.
	Timeout time.Duration
	Logf    func(string, ...any)
}

var _ UDPDialer = (*NetUDPDialer)(nil)

// DialUDP connects a UDP socket to dst.
func (d *NetUDPDialer) DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !dst.IsValid() || dst.Port() == 0 {
		return nil, fmt.Errorf("flow: dial udp: %v is not a destination", dst)
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultUDPDialTimeout
	}
	nd := net.Dialer{Timeout: timeout, Control: d.control}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// dst is a netip.AddrPort, so dst.String() cannot render a name and Go's
	// resolver is never consulted. The gate in nohostdial_test.go records the
	// review (MEASUREMENTS.md §5.4).
	c, err := nd.DialContext(ctx, udpNetworkFor(dst.Addr()), dst.String())
	if err != nil {
		return nil, fmt.Errorf("flow: dial udp %s: %w", dst, err)
	}
	return c, nil
}

// control pins the socket before connect. Unlike the TCP path there is no
// TCP_NODELAY to set: a datagram socket never coalesces, which is why
// emit.UDPTransport grants CapNoDelay truthfully.
func (d *NetUDPDialer) control(network, address string, c syscall.RawConn) error {
	if d.Interface == "" {
		return nil
	}
	var berr error
	if cerr := c.Control(func(fd uintptr) {
		berr = bindToInterface(fd, d.Interface, isV6Network(network, address))
	}); cerr != nil {
		return fmt.Errorf("flow: dial udp control: %w", cerr)
	}
	if berr != nil {
		return fmt.Errorf("flow: bind udp socket to %s: %w", d.Interface, berr)
	}
	return nil
}

// BindControl is the net.Dialer Control hook that pins every socket a
// stdlib dialer creates to iface, for the callers that must hand a *net.Dialer
// to somebody else rather than dial themselves.
//
// resolve.NewUDP is the one that matters: in TUN mode the capture routes cover
// the whole address space, so an unbound UDP/53 socket aimed at the chain's
// plaintext rung is routed straight back into our own netstack, answered by our
// own in-process resolver, and asked of the same chain again. That is not a
// detour, it is unbounded recursion — the one shape of loop the tunnel can
// build out of its own DNS defence. An empty iface returns a Control that does
// nothing, which is proxy mode.
func BindControl(iface string) func(network, address string, c syscall.RawConn) error {
	d := &NetUDPDialer{Interface: iface}
	return d.control
}

func udpNetworkFor(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "udp4"
	}
	return "udp6"
}

// SendFirstDatagram emits the first datagram of a flow, applying st to it.
//
// conn must be the connected socket the rest of the flow will be relayed on:
// the plan may lower the hop limit, and emit.Sender restores it on the same
// socket afterwards — a decoy sent on a different socket would carry a
// different source port and belong to no flow at all.
//
// A plain strategy is one write. Anything else is compiled against the socket's
// real capabilities, so a strategy the transport cannot satisfy is refused with
// the shortfall named instead of being quietly downgraded to a plain datagram
// the caller believes was desynced.
func SendFirstDatagram(ctx context.Context, conn net.Conn, first []byte,
	st strategy.Strategy, snd *emit.Sender, dstPort int) error {
	if conn == nil {
		return fmt.Errorf("flow: send first datagram: nil connection")
	}
	if len(first) == 0 {
		return fmt.Errorf("flow: send first datagram: nothing to send")
	}
	if st.IsPlain() {
		n, err := conn.Write(first)
		if err != nil {
			return fmt.Errorf("flow: send first datagram: %w", err)
		}
		if n != len(first) {
			return fmt.Errorf("flow: send first datagram: wrote %d of %d bytes", n, len(first))
		}
		return nil
	}

	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("flow: %s on %T: %w", st.Label(), conn, ErrNotDatagram)
	}
	t, err := emit.NewUDPTransport(uc)
	if err != nil {
		return fmt.Errorf("flow: %s: %w", st.Label(), err)
	}
	// The transport is NOT closed here: it wraps the caller's socket, which the
	// relay goes on using.
	m := tlsmsg.Parse(first, dstPort)
	plan, err := st.Build(first, m, t.Caps(), strategy.DefaultBudget())
	if err != nil {
		return fmt.Errorf("flow: build %s for a %s datagram: %w", st.Label(), m.Proto, err)
	}
	if snd == nil {
		snd = &defaultSender
	}
	if err := snd.Send(ctx, t, plan); err != nil {
		return fmt.Errorf("flow: emit %s: %w", st.Label(), err)
	}
	return nil
}
