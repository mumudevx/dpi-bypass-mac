package proxyfe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// resolveBudget bounds the pre-flight resolution below. It is generous relative
// to the chain's own per-rung deadline because the chain may walk several rungs
// before one answers (MEASUREMENTS.md §2 measures the first two dropped on this
// line), and it exists to bound a dead network rather than to tune anything.
const resolveBudget = 6 * time.Second

// serveConnect handles `CONNECT host:port`.
//
// ORDERING, and where it departs from docs/PLAN.md's data path A.
//
// The plan has step 5 dial, step 6 write "200 Connection established" only
// after the dial succeeded, and step 7 read the client's first message. Steps 6
// and 7 cannot be in that order for a judged flow: the client will not send its
// ClientHello until it has seen the 200, and flow.LadderRunner needs that
// ClientHello before it dials, because the whole design is that rung 1 carries
// the client's own first message unmodified. Dialling once to check, writing the
// 200, and then dialling again for the ladder would cost every CONNECT a second
// upstream connection to learn something the ladder is about to learn anyway.
//
// So: a flow that is NOT judged (ScopeBypass, ScopeDirect) dials first and gets
// the plan's ordering exactly — a dial failure is a clean 502 the browser can
// render. A judged flow gets a pre-flight through the resolver chain instead,
// which turns the common failure (a name that does not resolve, or resolves
// only to the ISP sinkhole) into that same renderable 502, and then the 200
// goes out before the hello is read. A dial failure after the 200 closes the
// tunnel, which the browser reports as a connection error. That is the honest
// residue of the ordering constraint, and it is never a silent success: the
// ladder never falls back to sending plain (docs/PLAN.md data path A step 12).
func (s *Server) serveConnect(ctx context.Context, client *bufConn, req *http.Request) {
	s.connect.Add(1)
	start := s.o.Now()

	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	host, port, err := splitHostPort(authority, 443)
	if err != nil {
		writeStatus(client, http.StatusBadRequest, err.Error())
		return
	}

	v := s.verdictFor(host, port)
	ev := s.newEvent(host, port, v)
	acked := false
	ack := func() error {
		acked = true
		_, werr := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		return werr
	}

	rerr := s.tunnel(ctx, client, target(host, port), v, ev, ack)
	if rerr != nil && !acked {
		writeStatus(client, http.StatusBadGateway, connectRemedy(host, rerr))
	}
	s.finish(ev, start, rerr)
}

// connectRemedy turns a failure into a body the person looking at the browser
// window can act on. A proxy that answers every failure with a bare 502 makes
// its user guess which of the network, the name and the tool is broken.
func connectRemedy(host string, err error) string {
	switch {
	case errors.Is(err, flow.ErrNoUpstream):
		return fmt.Sprintf("dpb: no TCP connection to %s could be opened, so no bypass strategy can help.\n%v",
			host, err)
	case errors.Is(err, flow.ErrLadderExhausted):
		return fmt.Sprintf("dpb: every strategy failed for %s. Run `dpb tune` to measure this line.\n%v",
			host, err)
	case errors.Is(err, flow.ErrNoResolver):
		return fmt.Sprintf("dpb: %s could not be resolved and dpb will not fall back to the system "+
			"resolver, which answers blocked names with the ISP sinkhole.\n%v", host, err)
	default:
		return fmt.Sprintf("dpb: %s: %v", host, err)
	}
}

// tunnel is the shared datapath for CONNECT and SOCKS5 CONNECT.
//
// ack writes the client's "the tunnel is open" acknowledgement. It is a
// callback because WHEN it happens differs by scope: an unjudged flow dials
// first, so a dial failure is still reportable in the proxy protocol; a judged
// flow has to acknowledge before it can read the first message it needs in
// order to dial at all.
func (s *Server) tunnel(ctx context.Context, client net.Conn, t flow.Target,
	v policy.Verdict, ev *observ.ConnEvent, ack func() error) error {
	if !judged(v) {
		up, err := s.o.Dial.DialTCP(ctx, t)
		if err != nil {
			return err
		}
		if err := ack(); err != nil {
			_ = up.Close()
			return err
		}
		_, rerr := s.relay(ctx, client, up, nil, ev)
		return rerr
	}

	if err := s.precheck(ctx, t.Name); err != nil {
		return err
	}
	if err := ack(); err != nil {
		return err
	}

	first, kind, meta, err := flow.ReadFirstMessage(client, t.Port, s.o.FirstMsg)
	if err != nil {
		return fmt.Errorf("proxyfe: read first message: %w", err)
	}
	if kind == flow.MsgServerFirst {
		// SMTP, IMAP, POP3, FTP and MySQL all speak first, and nothing was
		// buffered. There is nothing to judge and nothing to replay, so relay
		// both directions now: making a server-first protocol wait is a
		// deadlock rather than a delay.
		up, derr := s.o.Dial.DialTCP(ctx, t)
		if derr != nil {
			return derr
		}
		if ev != nil {
			ev.Strategy, ev.Attempts = "", 1
		}
		_, rerr := s.relay(ctx, client, up, nil, ev)
		return rerr
	}

	out, err := s.o.Ladder.Run(ctx, t, v, first, meta, nil)
	if ev != nil {
		fillOutcome(ev, out)
	}
	if out.Escalations() > 0 {
		s.escalated.Add(1)
	}
	if err != nil {
		return err
	}
	up, rerr := s.relay(ctx, client, out.Conn, out.Pre, ev)
	// The walk committed on the origin's first byte and cached the rung that
	// carried it. Only the relay knows whether the handshake behind that byte
	// ever completed, so it reports back before the flow is forgotten.
	s.o.Ladder.Settle(t, out.Spec, meta, up)
	return rerr
}

// precheck resolves the name before the tunnel is acknowledged.
//
// It costs nothing on the hot path — resolve.Chain caches, so the dial the
// ladder makes a moment later reuses this answer — and it buys back the failure
// report the CONNECT ordering above would otherwise lose. A name that resolves
// only to the ISP sinkhole is rejected by the chain's own poison detector, so
// this also catches the case MEASUREMENTS.md §5.4 describes.
func (s *Server) precheck(ctx context.Context, host string) error {
	if s.o.Resolve == nil || host == "" || isLiteral(host) {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, resolveBudget)
	defer cancel()
	if _, err := s.o.Resolve(rctx, host); err != nil {
		return fmt.Errorf("proxyfe: resolve %s: %w", host, err)
	}
	return nil
}

// writeStatus sends a minimal HTTP response. The connection is always closed
// afterwards, so no framing beyond Content-Length is needed and none is
// invented.
func writeStatus(w net.Conn, code int, body string) {
	if body != "" && body[len(body)-1] != '\n' {
		body += "\n"
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", code, http.StatusText(code), len(body), body)
}
