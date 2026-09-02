package proxyfe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// SOCKS5 UDP ASSOCIATE, RFC 1928 §7 — the unprivileged datagram path.
//
// It is the honest alternative to TUN mode for clients that support it: no
// root, no utun, no routes, and the same policy and the same emitter. What it
// cannot do is speak for the applications that do not implement it, which is
// why it complements TUN mode rather than replacing it.
//
// One asymmetry is worth stating plainly, because it is a real limitation
// rather than an implementation shortcut. In TUN mode a refused QUIC Initial is
// answered with an ICMP port-unreachable, and a browser marks the path
// QUIC-broken and retries over TCP within the same RTT. SOCKS5 has no
// per-datagram error channel at all — §7 defines a request header and nothing
// else — so a refusal here is a DROP, and the client discovers it by timing out
// its own QUIC handshake. That is worse for the user by exactly one QUIC
// timeout, and it is the reason the ICMP path exists in the tunnel.

const (
	// socksUDPHeaderMin is RSV(2) + FRAG(1) + ATYP(1) + one byte, which is the
	// shortest buffer that can carry a destination at all. The real bound is
	// per address type and is checked as the header is walked.
	socksUDPHeaderMin = 5
	// maxUDPDatagram bounds one relayed datagram. Larger than anything a
	// 1500-byte-MTU link delivers, with room for a jumbo DNS reply.
	maxUDPDatagram = 64 << 10
	// DefaultUDPIdle reaps a datagram session after this long with no traffic
	// in either direction. UDP has no FIN, so without a reaper every flow
	// leaks a socket and a goroutine for the life of the association.
	DefaultUDPIdle = 60 * time.Second
	// DefaultMaxUDPSessions bounds the upstream sockets one association may
	// hold open. A client that sends to a thousand destinations gets a
	// thousand sockets otherwise.
	DefaultMaxUDPSessions = 128
	// udpDNSPort is answered in process and never relayed.
	udpDNSPort = 53
	// udpQUICPort is the port the QUIC policy applies to.
	udpQUICPort = 443
	// udpSetupBudget bounds resolving and dialling one destination. It exists
	// because that work happens on the association's single reader goroutine,
	// where an unbounded chain walk would stall every other datagram.
	udpSetupBudget = 5 * time.Second
)

// sessionKey identifies one (client source, destination) pair.
func sessionKey(from netip.AddrPort, host string, port int) string {
	return fmt.Sprintf("%s|%s:%d", from, host, port)
}

// QUICPolicy decides what happens to a QUIC Initial addressed to a name we
// judge. A bypassed or unjudged flow is always relayed, whatever this says.
//
// The values and their names are the same as tunfe.QUICPolicy's, and a test
// pins the two together: one policy the user sets must not mean two things in
// the two front ends.
type QUICPolicy uint8

const (
	// QUICRefuse drops the Initial so the client falls back to TCP, where the
	// whole measured ladder applies. It is the zero value because it is the
	// shipped default. See the note above on what "refuse" can mean here.
	QUICRefuse QUICPolicy = iota
	// QUICRelay forwards the datagram verbatim.
	QUICRelay
	// QUICDesync emits the Initial through Options.QUICStrategy. Its efficacy
	// against Turkish DPI is unmeasured; it exists to be measured.
	QUICDesync
)

var quicPolicyNames = [...]string{"refuse", "relay", "desync"}

func (p QUICPolicy) String() string {
	if int(p) < len(quicPolicyNames) {
		return quicPolicyNames[p]
	}
	return fmt.Sprintf("quicpolicy(%d)", uint8(p))
}

// DNSAnswerer answers a DNS query in process. *resolve.Server satisfies it.
//
// It is declared structurally rather than imported so this package's dependency
// set does not grow a resolver; what matters here is only that a query to
// UDP/53 must never be relayed. Handing the ISP's resolver exactly the queries
// DoH exists to hide would give away the DNS defence to any client that used
// UDP ASSOCIATE.
type DNSAnswerer interface {
	Answer(ctx context.Context, query []byte) []byte
}

// serveUDPAssociate runs one UDP association for the life of its control
// connection.
//
// RFC 1928 §7: "A UDP association terminates when the TCP connection that the
// UDP ASSOCIATE request arrived on terminates." That is the only lifetime rule
// there is, and it is what stops a relay socket outliving the client that asked
// for it.
func (s *Server) serveUDPAssociate(ctx context.Context, client *bufConn) {
	if s.o.UDPDial == nil {
		// Nothing is wired to carry datagrams. The RFC's own answer beats a
		// socket the client would wait on forever.
		socksReply(client, socksRepCmdNotSupported)
		return
	}
	local, ok := localAddrOf(client)
	if !ok {
		socksReply(client, socksRepGeneralFailure)
		return
	}
	// The relay socket binds to the SAME address the client reached us on, so a
	// loopback proxy stays a loopback proxy: an association that listened on
	// 0.0.0.0 would relay datagrams for the whole network.
	pc, err := net.ListenUDP(udpNetworkFor(local.Addr()), &net.UDPAddr{IP: local.Addr().AsSlice()})
	if err != nil {
		s.logf("proxyfe: socks5 udp associate: bind on %s: %v", local.Addr(), err)
		socksReply(client, socksRepGeneralFailure)
		return
	}
	defer pc.Close()

	bound, ok := netip.AddrFromSlice(pc.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		socksReply(client, socksRepGeneralFailure)
		return
	}
	boundAP := netip.AddrPortFrom(bound.Unmap(), uint16(pc.LocalAddr().(*net.UDPAddr).Port))
	if err := socksReplyAddr(client, socksRepOK, boundAP); err != nil {
		return
	}
	// The handshake deadline must go, or the association dies ten seconds in
	// while the control connection sits idle exactly as the RFC intends.
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	s.udpAssoc.Add(1)

	a := &udpAssoc{
		s:        s,
		pc:       pc,
		peerHost: clientHost(client),
		sessions: map[string]*udpSession{},
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	flow.Safe("proxyfe/socks5-udp", s.o.Logf, func() {
		defer close(done)
		a.serve(ctx)
	})
	// Shutdown has to be able to end the wait below. Nothing else can: the
	// client is entitled to hold an idle control connection open for the life
	// of the association, so there is no deadline to expire, and a read that
	// only ends when the client says so would outlive the server.
	stop := make(chan struct{})
	flow.Safe("proxyfe/socks5-udp-closer", s.o.Logf, func() {
		select {
		case <-ctx.Done():
			_ = client.SetReadDeadline(time.Unix(1, 0))
		case <-stop:
		}
	})

	// Block on the control connection. Anything the client writes on it is
	// noise — the protocol says nothing more happens there — so this is really
	// a wait for EOF, and EOF is the end of the association.
	_, _ = io.Copy(io.Discard, client)
	close(stop)
	cancel()
	_ = pc.Close() // interrupts the blocking ReadFrom
	<-done
	a.closeAll()
}

// udpAssoc is one client's association: the relay socket, the sessions it has
// opened, and the client address it learned.
type udpAssoc struct {
	s  *Server
	pc *net.UDPConn
	// peerHost is the IP the control connection came from, and the only host
	// this association accepts datagrams from. RFC 1928 says to drop datagrams
	// from any source other than the recorded one; the recorded one is the
	// ASSOCIATE request's DST.ADDR, which in practice is 0.0.0.0 because the
	// client does not yet know the port it will send from — so the control
	// connection's own address is the honest reading, and the PORT is
	// deliberately not pinned: a stub resolver sends each query from a fresh
	// port, and one association is expected to carry all of them.
	peerHost netip.Addr

	mu       sync.Mutex
	sessions map[string]*udpSession
	closed   bool
}

// udpSession is one (client, destination) pair: a connected upstream socket and
// the reply header the client expects to see in front of every answer.
type udpSession struct {
	up  net.Conn
	hdr []byte // the client's own header, echoed on replies
}

func (a *udpAssoc) serve(ctx context.Context) {
	buf := make([]byte, maxUDPDatagram)
	for {
		n, from, err := a.pc.ReadFromUDP(buf)
		if n > 0 {
			ap := from.AddrPort()
			a.handle(ctx, buf[:n], netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// handle relays or refuses one client datagram.
func (a *udpAssoc) handle(ctx context.Context, datagram []byte, from netip.AddrPort) {
	if !a.acceptFrom(from) {
		a.s.udpRefused.Add(1)
		a.s.logf("proxyfe: socks5 udp: ignoring a datagram from %s; this association belongs to %s", from, a.peerHost)
		return
	}
	hdr, host, port, payload, err := parseSOCKSUDP(datagram)
	if err != nil {
		a.s.udpRefused.Add(1)
		a.s.logf("proxyfe: socks5 udp from %s: %v", from, err)
		return
	}

	// DNS never leaves the process when we have a resolver of our own, exactly
	// as in TUN mode.
	if port == udpDNSPort && a.s.o.DNS != nil {
		if reply := a.s.o.DNS.Answer(ctx, payload); len(reply) > 0 {
			a.reply(from, hdr, reply)
		}
		return
	}

	// The policy decides BEFORE a socket is opened. A refused Initial must cost
	// no upstream socket at all, exactly as in TUN mode.
	verdict := a.s.verdictFor(host, port)
	action := a.s.quicAction(verdict, port, payload)
	if action == quicRefuse {
		a.s.udpRefused.Add(1)
		a.s.logf("proxyfe: socks5 udp: refusing a QUIC Initial to %s:%d so the client falls back to TCP, "+
			"where the measured ladder applies; SOCKS5 has no way to say so, so the client will time out first",
			host, port)
		return
	}

	sess, err := a.session(ctx, from, hdr, host, port)
	if err != nil {
		a.s.udpRefused.Add(1)
		a.s.logf("proxyfe: socks5 udp to %s:%d: %v", host, port, err)
		return
	}

	if err := sess.up.SetWriteDeadline(a.s.o.Now().Add(a.s.udpIdle())); err != nil {
		return
	}
	switch action {
	case quicDesync:
		if err := flow.SendFirstDatagram(ctx, sess.up, payload, a.s.o.QUICStrategy, a.s.o.Sender, port); err != nil {
			// Fail closed: an Initial we could not desync is not relayed plain
			// for a name we judge.
			a.s.udpRefused.Add(1)
			a.s.logf("proxyfe: socks5 udp: %v; refusing the Initial rather than relaying it plain", err)
			a.closeSession(sess, from, host, port)
			return
		}
		return
	}
	if _, err := sess.up.Write(payload); err != nil {
		a.s.logf("proxyfe: socks5 udp write to %s:%d: %v", host, port, err)
		a.closeSession(sess, from, host, port)
	}
}

// acceptFrom reports whether this datagram came from the client that owns the
// association.
func (a *udpAssoc) acceptFrom(from netip.AddrPort) bool {
	return a.peerHost.IsValid() && from.Addr() == a.peerHost
}

// session finds or opens the upstream socket for one destination.
func (a *udpAssoc) session(ctx context.Context, from netip.AddrPort, hdr []byte, host string, port int) (*udpSession, error) {
	// The key is (client source, destination). A client that sends from several
	// ports — every stub resolver does — gets one upstream socket per source,
	// and each reply goes back to the port that asked.
	key := sessionKey(from, host, port)
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, fmt.Errorf("the association is closed")
	}
	if s, ok := a.sessions[key]; ok {
		a.mu.Unlock()
		return s, nil
	}
	if len(a.sessions) >= a.s.maxUDPSessions() {
		a.mu.Unlock()
		return nil, fmt.Errorf("this association already holds %d upstream sockets", a.s.maxUDPSessions())
	}
	a.mu.Unlock()

	// Setting a session up is the one blocking step on this goroutine: a named
	// destination is resolved through the chain, which on a censored line walks
	// several transports. It gets its own bound so one slow name cannot stall
	// every other datagram on the association.
	sctx, cancel := context.WithTimeout(ctx, udpSetupBudget)
	defer cancel()
	dst, err := a.s.resolveUDP(sctx, host, port)
	if err != nil {
		return nil, err
	}
	up, err := a.s.o.UDPDial.DialUDP(sctx, dst)
	if err != nil {
		return nil, err
	}
	sess := &udpSession{up: up, hdr: append([]byte(nil), hdr...)}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = up.Close()
		return nil, fmt.Errorf("the association is closed")
	}
	if existing, ok := a.sessions[key]; ok {
		// Another datagram raced us here; keep one socket per destination.
		a.mu.Unlock()
		_ = up.Close()
		return existing, nil
	}
	a.sessions[key] = sess
	a.mu.Unlock()

	flow.Safe("proxyfe/socks5-udp-reply", a.s.o.Logf, func() { a.pump(from, sess, key) })
	return sess, nil
}

// pump copies replies back to the client, each one framed with the header the
// client used to address the destination.
func (a *udpAssoc) pump(to netip.AddrPort, sess *udpSession, key string) {
	defer func() {
		_ = sess.up.Close()
		a.mu.Lock()
		if a.sessions[key] == sess {
			delete(a.sessions, key)
		}
		a.mu.Unlock()
	}()
	buf := make([]byte, maxUDPDatagram)
	for {
		if err := sess.up.SetReadDeadline(a.s.o.Now().Add(a.s.udpIdle())); err != nil {
			return
		}
		n, err := sess.up.Read(buf)
		if n > 0 {
			a.reply(to, sess.hdr, buf[:n])
		}
		if err != nil {
			// An idle session is reaped rather than reported: UDP has no FIN,
			// so the deadline IS the end of the session.
			return
		}
	}
}

// reply sends one datagram back to the client with its SOCKS5 header.
//
// The header is the one the CLIENT wrote, echoed. RFC 1928 has the reply carry
// the address the datagram came from, and for an address destination that is
// the same bytes; for a NAME destination there is no address the client would
// recognise, and every client keys its sessions on what it asked for.
func (a *udpAssoc) reply(to netip.AddrPort, hdr, payload []byte) {
	out := make([]byte, 0, len(hdr)+len(payload))
	out = append(out, hdr...)
	out = append(out, payload...)
	if _, err := a.pc.WriteToUDP(out, net.UDPAddrFromAddrPort(to)); err != nil {
		a.s.logf("proxyfe: socks5 udp reply to %s: %v", to, err)
	}
}

func (a *udpAssoc) closeSession(sess *udpSession, from netip.AddrPort, host string, port int) {
	key := sessionKey(from, host, port)
	a.mu.Lock()
	if a.sessions[key] == sess {
		delete(a.sessions, key)
	}
	a.mu.Unlock()
	_ = sess.up.Close()
}

// closeAll tears every upstream socket down when the control connection ends.
func (a *udpAssoc) closeAll() {
	a.mu.Lock()
	a.closed = true
	sessions := a.sessions
	a.sessions = map[string]*udpSession{}
	a.mu.Unlock()
	for _, s := range sessions {
		_ = s.up.Close()
	}
}

// quicAction is what the policy does with this datagram.
type quicAction uint8

const (
	quicPass   quicAction = iota // relay it verbatim
	quicRefuse                   // do not relay it
	quicDesync                   // emit it through the UDP strategy
)

// quicAction applies the QUIC policy. Both halves of the test matter: a
// bypassed or already-direct flow is never touched, because those are the hosts
// we have positive evidence about; and only an Initial is acted on, because a
// datagram in the middle of a session belongs to a connection the client
// already has.
func (s *Server) quicAction(v policy.Verdict, port int, payload []byte) quicAction {
	if s.o.QUIC == QUICRelay || port != udpQUICPort || !judged(v) {
		return quicPass
	}
	if _, ok := tlsmsg.ParseQUICInitial(payload); !ok {
		return quicPass
	}
	if s.o.QUIC == QUICDesync {
		return quicDesync
	}
	return quicRefuse
}

// resolveUDP turns the datagram's destination into an address.
//
// A name is resolved through the tool's own chain and nowhere else: this is the
// one place on the datagram path where a name exists at all, and Go's resolver
// would answer it with the BTK sinkhole (MEASUREMENTS.md §5.4). With no chain
// wired, a named destination is refused rather than guessed at.
func (s *Server) resolveUDP(ctx context.Context, host string, port int) (netip.AddrPort, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
	}
	if s.o.Resolve == nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %q", flow.ErrNoResolver, host)
	}
	addrs, err := s.o.Resolve(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, a := range addrs {
		if a.IsValid() {
			return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("the chain returned no usable address for %q", host)
}

func (s *Server) udpIdle() time.Duration {
	if s.o.UDPIdle > 0 {
		return s.o.UDPIdle
	}
	return DefaultUDPIdle
}

func (s *Server) maxUDPSessions() int {
	if s.o.MaxUDPSessions > 0 {
		return s.o.MaxUDPSessions
	}
	return DefaultMaxUDPSessions
}

// parseSOCKSUDP splits a client datagram into its header and payload.
//
// The header is returned as raw bytes because replies echo it verbatim, and
// re-encoding it would be a second parser to disagree with the first.
func parseSOCKSUDP(b []byte) (hdr []byte, host string, port int, payload []byte, err error) {
	if len(b) < socksUDPHeaderMin {
		// The per-address-type bounds below decide the rest; this only rejects
		// a buffer too short to hold RSV, FRAG, ATYP and one byte of address.
		return nil, "", 0, nil, fmt.Errorf("datagram is %d bytes, shorter than a SOCKS5 UDP header", len(b))
	}
	if b[0] != 0 || b[1] != 0 {
		return nil, "", 0, nil, fmt.Errorf("reserved bytes are %#x %#x, want zero", b[0], b[1])
	}
	if b[2] != 0 {
		// RFC 1928 makes fragment reassembly optional and lets an
		// implementation drop fragments. Reassembling would mean holding state
		// for a peer that can simply never send the last fragment.
		return nil, "", 0, nil, fmt.Errorf("fragment %d: fragmented datagrams are not relayed", b[2])
	}
	p := 4
	switch b[3] {
	case socksATYPv4:
		if len(b) < p+4+2 {
			return nil, "", 0, nil, fmt.Errorf("truncated IPv4 destination")
		}
		host = netip.AddrFrom4([4]byte(b[p : p+4])).String()
		p += 4
	case socksATYPv6:
		if len(b) < p+16+2 {
			return nil, "", 0, nil, fmt.Errorf("truncated IPv6 destination")
		}
		host = netip.AddrFrom16([16]byte(b[p : p+16])).Unmap().String()
		p += 16
	case socksATYPDomain:
		n := int(b[p])
		p++
		if n == 0 {
			return nil, "", 0, nil, fmt.Errorf("empty destination name")
		}
		if len(b) < p+n+2 {
			return nil, "", 0, nil, fmt.Errorf("truncated destination name")
		}
		host = string(b[p : p+n])
		p += n
	default:
		return nil, "", 0, nil, fmt.Errorf("address type %d is not supported", b[3])
	}
	port = int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if port == 0 {
		return nil, "", 0, nil, fmt.Errorf("port 0 is not a destination")
	}
	// Normalise the way CONNECT and the SOCKS5 request path do, so one rule
	// cannot match a name here and miss it there.
	h, pt, serr := splitHostPort(hostPort(host, port), port)
	if serr != nil {
		return nil, "", 0, nil, serr
	}
	return b[:p], h, pt, b[p:], nil
}

// socksReplyAddr sends a reply carrying a real bound address.
//
// Unlike CONNECT, where every client ignores BND.ADDR, UDP ASSOCIATE's reply IS
// the relay's address: a client that cannot read it has nowhere to send its
// datagrams.
func socksReplyAddr(w io.Writer, rep byte, bound netip.AddrPort) error {
	out := []byte{socks5Version, rep, 0x00}
	a := bound.Addr().Unmap()
	if a.Is4() {
		out = append(out, socksATYPv4)
		v4 := a.As4()
		out = append(out, v4[:]...)
	} else {
		out = append(out, socksATYPv6)
		v6 := a.As16()
		out = append(out, v6[:]...)
	}
	out = binary.BigEndian.AppendUint16(out, bound.Port())
	_, err := w.Write(out)
	return err
}

// localAddrOf is the address the client reached this proxy on.
func localAddrOf(c net.Conn) (netip.AddrPort, bool) {
	ta, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := ta.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ap.Addr().IsValid()
}

// clientHost is the IP the control connection came from, which is the only host
// this association will accept datagrams from.
func clientHost(c net.Conn) netip.Addr {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}
	}
	return ta.AddrPort().Addr().Unmap()
}

func udpNetworkFor(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "udp4"
	}
	return "udp6"
}
