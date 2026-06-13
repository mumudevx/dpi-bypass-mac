// Package proxy is the no-sudo front-end: a local HTTP CONNECT (and plain HTTP)
// proxy that hands the first client payload to the desync engine before relaying
// the rest of the connection verbatim.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Resolver resolves a host to IPs (implemented by internal/dns.Chain).
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]net.IP, error)
}

// Options configures a Server.
type Options struct {
	Resolver    Resolver
	Apply       ApplyFunc // applies desync to the first payload
	DesyncPorts map[int]bool
	SkipHost    func(host string) bool
	DialTimeout time.Duration
	Logf        func(format string, args ...any)
}

// ApplyFunc writes the first payload to upstream using the desync engine.
type ApplyFunc func(ctx context.Context, upstream *net.TCPConn, first []byte, dstPort int) error

// Server is a local interception proxy.
type Server struct {
	opt Options
}

// New builds a Server.
func New(opt Options) *Server {
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 10 * time.Second
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.SkipHost == nil {
		opt.SkipHost = func(string) bool { return false }
	}
	return &Server{opt: opt}
}

// ListenAndServe accepts connections on addr until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.opt.Logf("accept: %v", err)
			continue
		}
		go s.handle(ctx, conn)
	}
}

// dialUpstream resolves host and dials the first IP that connects, returning a
// *net.TCPConn with TCP_NODELAY so each engine Write tends to its own segment.
func (s *Server) dialUpstream(ctx context.Context, host string, port int) (*net.TCPConn, error) {
	ips, err := s.opt.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: s.opt.DialTimeout}
	var lastErr error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
		if err != nil {
			lastErr = err
			continue
		}
		tcp := c.(*net.TCPConn)
		_ = tcp.SetNoDelay(true)
		return tcp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address for %s", host)
	}
	return nil, lastErr
}

func (s *Server) shouldDesync(host string, port int) bool {
	if !s.opt.DesyncPorts[port] {
		return false
	}
	return !s.opt.SkipHost(host)
}
