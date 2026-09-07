package resolve

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/mumudevx/dpb/internal/flow"
)

const (
	// udpQueryMax is the largest datagram accepted from a stub. 4096 covers
	// every EDNS0 buffer size a stub advertises in practice.
	udpQueryMax = 4096
	// tcpIdle closes a stub's TCP connection that has stopped asking. RFC 7766
	// wants connection reuse, so this is generous rather than aggressive.
	tcpIdle = 30 * time.Second
	// tcpWrite bounds one reply write so a stuck stub cannot pin a goroutine.
	tcpWrite = 5 * time.Second
	// inFlightMax bounds concurrent upstream work. A stub loop or a hostile
	// local process must not be able to turn one query per packet into one
	// goroutine plus one upstream exchange per packet.
	inFlightMax = 256
	// dropLogEvery rate-limits the over-budget log line. Logging every drop
	// during a flood would move the stall from the upstream exchange onto
	// stderr, which is the same bug in a different place.
	dropLogEvery = 1024
)

// Server answers DNS for local stubs, over UDP and over TCP.
//
// TCP is served here on purpose. MEASUREMENTS.md §2 measures upstream TCP/53 as
// connection-reset at every port tested, so an application that receives TC=1
// and retries over TCP would fail on this ISP — unless the retry never leaves
// the machine. It does not: this server answers it in process from the same
// chain, whose own upstream transports remain DoH, DoT and alternate-port UDP.
type Server struct {
	chain   *Chain
	logf    func(string, ...any)
	sem     chan struct{}
	dropped atomic.Uint64
}

func NewServer(c *Chain, logf func(string, ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{chain: c, logf: logf, sem: make(chan struct{}, inFlightMax)}
}

// Answer resolves one query and always returns a message a stub can parse. It
// never returns an error: a stub that gets nothing waits out its own timeout
// and then does the one thing that provably cannot work here.
func (s *Server) Answer(ctx context.Context, query []byte) []byte {
	if len(query) < headerLen {
		return nil // Not a DNS message at all; there is nothing to reply to.
	}
	if IsResponse(query) {
		return nil // A response arriving as a query is noise or a reflection attempt.
	}
	if s.chain == nil {
		return SynthRcode(query, dns.RcodeServerFailure)
	}
	if _, err := FirstQuestion(query); err != nil {
		s.logf("resolve: server: unusable query: %v", err)
		return SynthRcode(query, dns.RcodeFormatError)
	}
	// ExchangeServed, not Exchange: this answer is leaving the process, so the
	// AAAA policy is the fail-closed one (resolve.Options.V6Protected).
	msg, err := s.chain.ExchangeServed(ctx, query)
	if err != nil {
		s.logf("resolve: server: %v", err)
	}
	if len(msg) < headerLen {
		return SynthRcode(query, dns.RcodeServerFailure)
	}
	return msg
}

// ServeUDP answers queries on pc until ctx is cancelled or the socket fails.
func (s *Server) ServeUDP(ctx context.Context, pc net.PacketConn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.closeOnDone(ctx, pc.Close, "resolve.server.udp.closer")

	buf := make([]byte, udpQueryMax)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if n > 0 {
			query := make([]byte, n)
			copy(query, buf[:n])
			s.dispatch("resolve.server.udp", func() {
				resp := s.Answer(ctx, query)
				if len(resp) == 0 {
					return
				}
				if _, werr := pc.WriteTo(resp, addr); werr != nil {
					s.logf("resolve: server: write to %s: %v", addr, werr)
				}
			})
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("resolve: server: read UDP: %w", err)
		}
	}
}

// ServeTCP answers length-prefixed queries on l until ctx is cancelled.
func (s *Server) ServeTCP(ctx context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.closeOnDone(ctx, l.Close, "resolve.server.tcp.closer")

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("resolve: server: accept: %w", err)
		}
		flow.Safe("resolve.server.tcp", s.logf, func() {
			defer conn.Close()
			s.serveTCPConn(ctx, conn)
		})
	}
}

func (s *Server) serveTCPConn(ctx context.Context, conn net.Conn) {
	for {
		if err := conn.SetReadDeadline(time.Now().Add(tcpIdle)); err != nil {
			return
		}
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.logf("resolve: server: TCP length read: %v", err)
			}
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n < headerLen {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp := s.Answer(ctx, query)
		if len(resp) == 0 {
			return
		}
		if Truncated(resp) {
			// TC is meaningless on a stream: RFC 7766 §8 has the server send
			// the whole answer here, and a stub that asked over TCP *because*
			// of a TC=1 UDP answer has nowhere left to escalate to. Serving it
			// TC=1 again is a silent resolution failure; SERVFAIL is a failure
			// it can see. The chain never reaches plaintext TCP/53 for a
			// second opinion — MEASUREMENTS.md §2 measures that as
			// connection-reset at every port.
			s.logf("resolve: server: refusing to serve a truncated answer over TCP for %s", questionLabel(query))
			resp = SynthRcode(query, dns.RcodeServerFailure)
		}
		if len(resp) > 0xffff {
			resp = SynthRcode(query, dns.RcodeServerFailure)
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
		copy(out[2:], resp)
		if err := conn.SetWriteDeadline(time.Now().Add(tcpWrite)); err != nil {
			return
		}
		if _, err := conn.Write(out); err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// dispatch runs fn on a guarded goroutine, and drops the query when the
// in-flight budget is spent.
//
// It must never run fn on the caller's goroutine. This is called from the
// ServeUDP read loop, which owns the socket the whole machine's stub resolver
// talks to, so running one Chain.Exchange inline stalls DNS for every other
// process behind it: measured, 4000 queries from one socket against a 300 ms
// upstream left an unrelated single query answered after 6.85 s. That branch
// was also the only one outside flow.Safe, so a panic reachable from
// Chain.Exchange killed the process under load alone — exactly what the panic
// barrier exists to prevent.
//
// Dropping is the honest failure: a stub that gets nothing retries, and its
// TCP retry is answered in process by ServeTCP from the same chain.
func (s *Server) dispatch(name string, fn func()) bool {
	select {
	case s.sem <- struct{}{}:
		flow.Safe(name, s.logf, func() {
			defer func() { <-s.sem }()
			fn()
		})
		return true
	default:
		if n := s.dropped.Add(1); (n-1)%dropLogEvery == 0 {
			s.logf("resolve: server: %d queries dropped: more than %d exchanges already in flight", n, inFlightMax)
		}
		return false
	}
}

// Dropped counts queries refused because the in-flight budget was spent.
func (s *Server) Dropped() uint64 { return s.dropped.Load() }

// closeOnDone closes a listener when the context is cancelled, which is the
// only way to interrupt a blocking Accept or ReadFrom.
func (s *Server) closeOnDone(ctx context.Context, closer func() error, name string) {
	var once sync.Once
	flow.Safe(name, s.logf, func() {
		<-ctx.Done()
		once.Do(func() { _ = closer() })
	})
}
