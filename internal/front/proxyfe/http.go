package proxyfe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/httpmsg"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// serveHTTP drives one client connection through the HTTP proxy protocol.
//
// It LOOPS, reading one request at a time, and dials a FRESH upstream for each
// one. That is the fix for a defect the previous implementation shipped: it
// dialled an upstream for the first request's host and then tunnelled the rest
// of the client connection into it, so a second request on the same connection
// addressed to a different origin was delivered to the first origin's backend.
// Go's own http.Transport makes the same mistake easy to reproduce — it drops
// the target address from the connection-pool key for http-scheme targets
// reached through a proxy — which is why nothing here uses a Transport.
func (s *Server) serveHTTP(ctx context.Context, client *bufConn) {
	for {
		if err := client.SetReadDeadline(s.o.Now().Add(s.o.ClientIdle)); err != nil {
			return
		}
		req, err := http.ReadRequest(client.r)
		if err != nil {
			// A client that closed, or timed out holding the connection open,
			// is ordinary and silent. A request line we could not parse is not:
			// answering 400 tells the client which end is confused, where
			// closing without a word looks like the proxy crashed.
			if !quietReadFailure(err) {
				writeStatus(client, http.StatusBadRequest, "dpb: "+err.Error())
			}
			return
		}
		if err := client.SetReadDeadline(time.Time{}); err != nil {
			return
		}

		switch {
		case req.Method == http.MethodConnect:
			s.serveConnect(ctx, client, req)
			return
		case req.URL == nil || !req.URL.IsAbs():
			// Origin-form: the request is addressed to the proxy itself, not
			// through it. That is the PAC fetch, and nothing else.
			if !s.serveLocal(client, req) {
				return
			}
		default:
			if !s.serveForward(ctx, client, req) {
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// quietReadFailure reports whether a failed request read is the ordinary end of
// a client connection rather than a protocol error worth answering.
func quietReadFailure(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// serveLocal answers a request addressed to the listener itself. It reports
// whether the connection may carry another request.
func (s *Server) serveLocal(client net.Conn, req *http.Request) bool {
	drainBody(req)
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	if s.o.PAC == nil || path != PACPath {
		writeStatus(client, http.StatusNotFound,
			"dpb is a proxy. Point your system at it, or fetch "+PACPath+" for the auto-proxy script.")
		return false
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		writeStatus(client, http.StatusMethodNotAllowed, "dpb: "+PACPath+" is GET-only")
		return false
	}
	s.pacHits.Add(1)
	body := s.o.PAC.Script()

	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/x-ns-proxy-autoconfig\r\n"+
		"Content-Length: %d\r\n"+
		// macOS re-fetches the PAC on its own schedule and a stale copy would
		// keep pointing at a listener that has moved or gone.
		"Cache-Control: no-store\r\n"+
		"Connection: close\r\n\r\n", len(body))
	if req.Method == http.MethodGet {
		b.Write(body)
	}
	_, _ = client.Write(b.Bytes())
	return false
}

// serveForward proxies one plaintext request to its own origin. It reports
// whether the client connection may carry another request.
func (s *Server) serveForward(ctx context.Context, client net.Conn, req *http.Request) bool {
	s.httpReqs.Add(1)
	start := s.o.Now()

	if req.URL.Scheme != "http" {
		drainBody(req)
		writeStatus(client, http.StatusBadRequest,
			"dpb: "+req.URL.Scheme+":// cannot be proxied in the clear; use CONNECT")
		return false
	}
	host, port, err := splitHostPort(hostOf(req), 80)
	if err != nil {
		drainBody(req)
		writeStatus(client, http.StatusBadRequest, err.Error())
		return false
	}

	v := s.verdictFor(host, port)
	ev := s.newEvent(host, port, v)
	head, err := originHead(req)
	if err != nil {
		drainBody(req)
		writeStatus(client, http.StatusBadRequest, err.Error())
		s.finish(ev, start, err)
		return false
	}

	up, pre, err := s.openHTTP(ctx, target(host, port), v, head, port, ev)
	if err != nil {
		drainBody(req)
		writeStatus(client, http.StatusBadGateway, connectRemedy(host, err))
		s.finish(ev, start, err)
		return false
	}
	counted := &countConn{Conn: up}
	counted.up.Add(int64(len(head)))
	counted.down.Add(int64(len(pre)))
	defer up.Close()
	// The byte counts have to be copied onto the event BEFORE it is published,
	// which a deferred assignment cannot do: finish runs first and would report
	// a flow that moved nothing.
	settle := func(err error) {
		ev.BytesUp, ev.BytesDown = counted.up.Load(), counted.down.Load()
		s.finish(ev, start, err)
	}

	if err := writeBody(counted, req); err != nil {
		settle(err)
		return false
	}

	upr := bufio.NewReader(io.MultiReader(bytes.NewReader(pre), counted))
	resp, err := http.ReadResponse(upr, req)
	if err != nil {
		writeStatus(client, http.StatusBadGateway, fmt.Sprintf("dpb: %s sent no usable response: %v", host, err))
		settle(err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		// The origin agreed to change protocol. Everything after the response
		// head is opaque in both directions, so hand the rest over to the relay
		// with whatever the response reader has already buffered.
		err := s.upgrade(ctx, client, counted, upr, resp)
		settle(err)
		return false
	}

	stripHopByHop(resp.Header)
	if err := resp.Write(client); err != nil {
		settle(err)
		return false
	}
	settle(nil)
	// resp.Close is set when the response is delimited by the connection
	// closing, which we cannot reframe without buffering the whole body: the
	// client connection has to end with it.
	return !resp.Close && !req.Close
}

// openHTTP gets an upstream for one plaintext request, through the ladder when
// the flow is judged and directly when it is not.
func (s *Server) openHTTP(ctx context.Context, t flow.Target, v policy.Verdict,
	head []byte, port int, ev *observ.ConnEvent) (net.Conn, []byte, error) {
	if !judged(v) {
		up, err := s.o.Dial.DialTCP(ctx, t)
		if err != nil {
			return nil, nil, err
		}
		if _, err := up.Write(head); err != nil {
			_ = up.Close()
			return nil, nil, err
		}
		return up, nil, nil
	}

	if err := s.precheck(ctx, t.Name); err != nil {
		return nil, nil, err
	}
	out, err := s.o.Ladder.Run(ctx, t, v, head, tlsmsg.Parse(head, port), nil)
	if ev != nil {
		fillOutcome(ev, out)
	}
	if out.Escalations() > 0 {
		s.escalated.Add(1)
	}
	if err != nil {
		return nil, nil, err
	}
	return out.Conn, out.Pre, nil
}

// upgrade relays an accepted protocol upgrade.
func (s *Server) upgrade(ctx context.Context, client, up net.Conn, upr *bufio.Reader, resp *http.Response) error {
	stripHopByHopExceptUpgrade(resp.Header)
	if err := resp.Write(client); err != nil {
		return err
	}
	return s.relay(ctx, client, &bufConn{Conn: up, r: upr}, nil, nil)
}

// hostOf is the authority the request is addressed to. RFC 9112 says the Host
// header wins for a proxy request, but a client that sent an absolute-form
// target and no Host — legal in HTTP/1.0 — still has to be served.
func hostOf(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

// hopByHop are the headers a proxy consumes rather than forwards (RFC 9110
// §7.6.1). Transfer-Encoding and Content-Length are here because this code
// re-derives both from the parsed request rather than trusting what was
// written: a request carrying both is the classic request-smuggling shape, and
// re-deriving makes the two agree by construction.
var hopByHop = []string{
	"Connection",
	"Proxy-Connection",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Content-Length",
	"Upgrade",
}

func stripHopByHop(h http.Header) {
	// A Connection header names further headers that are themselves hop-by-hop.
	for _, name := range h.Values("Connection") {
		for _, tok := range strings.Split(name, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				h.Del(tok)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// stripHopByHopExceptUpgrade keeps the two headers a 101 response needs to mean
// anything to the client.
func stripHopByHopExceptUpgrade(h http.Header) {
	upgrade, conn := h.Get("Upgrade"), h.Get("Connection")
	stripHopByHop(h)
	if upgrade != "" {
		h.Set("Upgrade", upgrade)
		h.Set("Connection", conn)
	}
}

// originHead renders the request as an ORIGIN-FORM head: the bytes that go on
// the wire to the origin, and the bytes the ladder judges and may reframe.
//
// It is built here rather than with http.Request.Write because the head and the
// body have to be separable: the head is the first message the strategy layer
// operates on, and the body is ordinary relay traffic that follows it.
func originHead(req *http.Request) ([]byte, error) {
	if req.Host == "" && req.URL.Host == "" {
		return nil, fmt.Errorf("proxyfe: request carries no Host")
	}
	h := req.Header.Clone()
	upgrade, connection := h.Get("Upgrade"), h.Get("Connection")
	stripHopByHop(h)
	// Upgrade and its Connection token are hop-by-hop by the letter of RFC
	// 9110, and stripping them is right for every hop EXCEPT the one being
	// asked to upgrade. A proxy that removes them turns a WebSocket handshake
	// into an ordinary GET that the origin answers 200 to, and the client hangs
	// waiting for frames that will never come.
	if upgrade != "" && containsToken(connection, "upgrade") {
		h.Set("Upgrade", upgrade)
		h.Set("Connection", "Upgrade")
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	// Host goes first because that is where every real client puts it and
	// because the host mutators in internal/ops locate it by scanning forward.
	fmt.Fprintf(&b, "Host: %s\r\n", hostOf(req))

	switch {
	case chunked(req.TransferEncoding):
		b.WriteString("Transfer-Encoding: chunked\r\n")
	case req.ContentLength > 0:
		fmt.Fprintf(&b, "Content-Length: %d\r\n", req.ContentLength)
	}

	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	// Deterministic order. http.Header is a map, so the request's own header
	// order was lost by the parser; sorting at least makes the bytes we emit a
	// function of the request rather than of a hash seed, which is what makes a
	// golden test of the emitted head meaningful.
	sort.Strings(names)
	for _, k := range names {
		for _, val := range h[k] {
			if !validHeaderValue(val) {
				return nil, fmt.Errorf("proxyfe: header %s carries a control character", k)
			}
			fmt.Fprintf(&b, "%s: %s\r\n", k, val)
		}
	}
	b.WriteString("\r\n")
	if b.Len() > httpmsg.MaxHead {
		return nil, fmt.Errorf("proxyfe: request head is %d bytes, over the %d-byte limit", b.Len(), httpmsg.MaxHead)
	}
	return b.Bytes(), nil
}

// containsToken reports whether a comma-separated header value names tok,
// case-insensitively.
func containsToken(v, tok string) bool {
	for _, part := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(part), tok) {
			return true
		}
	}
	return false
}

func chunked(te []string) bool {
	for _, v := range te {
		if strings.EqualFold(v, "chunked") {
			return true
		}
	}
	return false
}

// validHeaderValue rejects the CR and LF that would let a header value inject a
// second request into the stream we are about to write.
func validHeaderValue(v string) bool {
	return !strings.ContainsAny(v, "\r\n\x00")
}

// writeBody forwards the request body, re-chunking it when the client sent it
// chunked. Go's parser decodes chunked framing into a plain stream, so writing
// req.Body straight out would silently strip the framing the origin is
// expecting.
func writeBody(up net.Conn, req *http.Request) error {
	if req.Body == nil {
		return nil
	}
	defer req.Body.Close()
	if chunked(req.TransferEncoding) {
		cw := httputil.NewChunkedWriter(up)
		if _, err := io.Copy(cw, req.Body); err != nil {
			return fmt.Errorf("proxyfe: forward chunked body: %w", err)
		}
		if err := cw.Close(); err != nil {
			return fmt.Errorf("proxyfe: end chunked body: %w", err)
		}
		if _, err := up.Write([]byte("\r\n")); err != nil {
			return fmt.Errorf("proxyfe: end chunked body: %w", err)
		}
		return nil
	}
	if req.ContentLength <= 0 {
		return nil
	}
	if _, err := io.Copy(up, req.Body); err != nil {
		return fmt.Errorf("proxyfe: forward body: %w", err)
	}
	return nil
}

// drainBody consumes a request body we are not forwarding, so the next request
// on the connection starts where it should. The cap is there because an
// unbounded drain is a way to make us read forever.
func drainBody(req *http.Request) {
	if req.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, maxDrain))
	_ = req.Body.Close()
}

const maxDrain = 1 << 20
