package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
)

const firstChunkMax = 16 * 1024

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	br := bufio.NewReader(raw)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(ctx, raw, br, req.Host)
		return
	}
	s.handleHTTP(ctx, raw, br, req)
}

// handleConnect tunnels an HTTPS CONNECT, fragmenting the first client payload
// (the TLS ClientHello) through the desync engine.
func (s *Server) handleConnect(ctx context.Context, client net.Conn, br *bufio.Reader, hostport string) {
	host, port := hostPort(hostport, 443)
	upstream, err := s.dialUpstream(ctx, host, port)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		s.opt.Logf("connect %s: %v", hostport, err)
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	// Read the first client payload (the ClientHello) and apply desync.
	buf := make([]byte, firstChunkMax)
	n, _ := br.Read(buf)
	if n > 0 {
		first := buf[:n]
		if s.shouldDesync(host, port) {
			if err := s.opt.Apply(ctx, upstream, first, port); err != nil {
				s.opt.Logf("apply %s: %v", host, err)
				return
			}
		} else if _, err := upstream.Write(first); err != nil {
			return
		}
	}
	tunnel(br, client, upstream)
}

// handleHTTP forwards a plaintext HTTP request, applying Host-header tricks and
// fragmentation to the first request. Best-effort single-request forwarding.
func (s *Server) handleHTTP(ctx context.Context, client net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.URL.Hostname()
	if host == "" {
		host, _ = hostPort(req.Host, 80)
	}
	port := 80
	if p := req.URL.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	upstream, err := s.dialUpstream(ctx, host, port)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		s.opt.Logf("http %s: %v", host, err)
		return
	}
	defer upstream.Close()

	req.RequestURI = ""
	var head bytes.Buffer
	if err := req.Write(&head); err != nil {
		return
	}
	first := head.Bytes()
	if s.shouldDesync(host, port) {
		if err := s.opt.Apply(ctx, upstream, first, port); err != nil {
			s.opt.Logf("apply %s: %v", host, err)
			return
		}
	} else if _, err := upstream.Write(first); err != nil {
		return
	}
	tunnel(br, client, upstream)
}

// tunnel relays bytes in both directions until either side closes.
func tunnel(clientReader io.Reader, client, upstream net.Conn) {
	var once sync.Once
	closeBoth := func() { client.Close(); upstream.Close() }
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, clientReader); once.Do(closeBoth); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); once.Do(closeBoth); done <- struct{}{} }()
	<-done
	<-done
}

func hostPort(hostport string, defPort int) (string, int) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, defPort
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return h, defPort
	}
	return h, n
}
