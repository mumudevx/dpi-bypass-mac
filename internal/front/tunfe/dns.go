package tunfe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DNS in TUN mode, and why it is answered here rather than relayed.
//
// Relaying UDP/53 would hand the ISP's resolver exactly the queries DoH exists
// to hide, so the whole DNS-poisoning defence would be lost the moment the user
// ran with sudo. Both transports are therefore served in process from the same
// resolve.Chain proxy mode uses, and every answer feeds policy.ReverseMap on
// its way out — which is what names the TCP flow that follows a moment later.
//
// TCP/53 into the tunnel is served locally too, and that is unusual: no tool in
// the dossier does it. It matters here because MEASUREMENTS.md §2 measures
// upstream TCP/53 as connection-reset at every port on this line, so an
// application that receives TC=1 and retries over TCP would fail — unless the
// retry never leaves the machine.

const (
	// dnsExchangeTimeout bounds one query against the chain. The chain has five
	// rungs and its own per-rung deadline, so this is the outer bound that
	// keeps a fully dead network from pinning a session goroutine.
	dnsExchangeTimeout = 8 * time.Second
)

// serveDNSDatagrams answers queries on one UDP/53 session until it goes idle.
func (s *Server) serveDNSDatagrams(client net.Conn, dst netip.AddrPort) {
	if s.o.DNS == nil {
		// Nothing can answer, and relaying is the one thing this path must
		// never do. Dropping makes the stub retry and then time out, which is
		// visible; a relayed query is invisible and poisoned.
		s.logf("tunfe: dropping a DNS query to %s: no in-process resolver is wired, "+
			"and relaying it would hand the ISP the queries DoH exists to hide", dst)
		return
	}
	idle := s.o.UDPIdle
	buf := make([]byte, maxDatagram)
	for {
		if err := client.SetReadDeadline(s.o.Now().Add(idle)); err != nil {
			return
		}
		n, err := client.Read(buf)
		if n > 0 {
			query := make([]byte, n)
			copy(query, buf[:n])
			ctx, cancel := context.WithTimeout(s.ctx, dnsExchangeTimeout)
			resp := s.o.DNS.Answer(ctx, query)
			cancel()
			if len(resp) > 0 {
				if werr := client.SetWriteDeadline(s.o.Now().Add(idle)); werr != nil {
					return
				}
				if _, werr := client.Write(resp); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// serveDNSStream answers length-prefixed queries on one TCP/53 connection.
//
// It reuses resolve.Server.ServeTCP rather than reimplementing the 2-byte
// framing, because that server already refuses to serve a truncated answer over
// a stream — there is nowhere left for a stub to escalate to, so TC=1 on TCP is
// a silent resolution failure where SERVFAIL is a visible one.
func (s *Server) serveDNSStream(ctx context.Context, client net.Conn) {
	if s.o.DNS == nil {
		s.logf("tunfe: dropping a DNS connection: no in-process resolver is wired")
		return
	}
	ln := newOneConnListener(client)
	if err := s.o.DNS.ServeTCP(ctx, ln); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logf("tunfe: serve TCP DNS: %v", err)
	}
}

// oneConnListener presents a single already-accepted connection as a
// net.Listener.
//
// resolve.Server owns the DNS framing and speaks Listener; the netstack's TCP
// forwarder hands out connections. This is the adapter between them, and it
// closes itself when its one connection closes so the server loop ends with the
// session instead of outliving it.
type oneConnListener struct {
	ch     chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

var _ net.Listener = (*oneConnListener)(nil)

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{
		ch:     make(chan net.Conn, 1),
		addr:   c.LocalAddr(),
		closed: make(chan struct{}),
	}
	l.ch <- &closeNotifyConn{Conn: c, notify: l.Close}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.addr }

// closeNotifyConn closes the listener that produced it when it closes, so a
// finished session ends the accept loop rather than leaving it parked until the
// process exits.
type closeNotifyConn struct {
	net.Conn
	once   sync.Once
	notify func() error
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.notify != nil {
			_ = c.notify()
		}
	})
	return err
}
