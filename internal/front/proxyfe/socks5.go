package proxyfe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// SOCKS5, RFC 1928. Only CONNECT is implemented, and only with no
// authentication: the listener is on loopback, so a credential would protect
// nothing that the loopback bind does not already protect, and asking for one
// would break every client that expects a local proxy to be open.
const (
	socks5Version = 0x05

	socksMethodNone       = 0x00 // no authentication required
	socksMethodNoneAccept = 0xFF

	socksCmdConnect      = 0x01
	socksCmdBind         = 0x02
	socksCmdUDPAssociate = 0x03

	socksATYPv4     = 0x01
	socksATYPDomain = 0x03
	socksATYPv6     = 0x04

	socksRepOK               = 0x00
	socksRepGeneralFailure   = 0x01
	socksRepHostUnreach      = 0x04
	socksRepRefused          = 0x05
	socksRepCmdNotSupported  = 0x07
	socksRepATYPNotSupported = 0x08
)

// maxSOCKSHandshake bounds the greeting and request read. The handshake is at
// most 262 + 262 bytes, so this is a guard against a peer that opens a
// connection and dribbles.
const maxSOCKSHandshake = 10 * time.Second

// serveSOCKS handles one SOCKS5 client.
//
// The name is preserved. ATYP=3 carries the hostname the application asked for,
// so a SOCKS5 client defeats DNS censorship for free in exactly the way a
// CONNECT client does: the application's own resolution never happens, and the
// name reaches policy and the ladder intact. Resolving it here and reconnecting
// by address would throw that away.
func (s *Server) serveSOCKS(ctx context.Context, client *bufConn) {
	start := s.o.Now()
	if err := client.SetDeadline(s.o.Now().Add(maxSOCKSHandshake)); err != nil {
		return
	}

	if err := socksGreet(client); err != nil {
		s.logf("proxyfe: socks5 greeting from %s: %v", client.RemoteAddr(), err)
		return
	}

	cmd, host, port, err := socksRequest(client)
	if err != nil {
		s.logf("proxyfe: socks5 request from %s: %v", client.RemoteAddr(), err)
		socksReply(client, socksRepGeneralFailure)
		return
	}
	switch cmd {
	case socksCmdConnect:
		if port == 0 {
			s.logf("proxyfe: socks5 connect from %s: port 0 is not a destination", client.RemoteAddr())
			socksReply(client, socksRepGeneralFailure)
			return
		}
	case socksCmdUDPAssociate:
		// The unprivileged datagram path. The request's DST.ADDR/DST.PORT are
		// what the client EXPECTS to send from, not a destination; they are
		// deliberately not trusted, because the association learns the client's
		// real source from its first datagram and pins it.
		s.serveUDPAssociate(ctx, client)
		return
	default:
		// BIND is not implemented and never will be: it asks this process to
		// accept inbound connections on the user's behalf, which no browser
		// wants and no censorship problem needs.
		s.logf("proxyfe: socks5 %s from %s: command %d not supported", host, client.RemoteAddr(), cmd)
		socksReply(client, socksRepCmdNotSupported)
		return
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}

	v := s.verdictFor(host, port)
	ev := s.newEvent(host, port, v)
	acked := false
	ack := func() error {
		acked = true
		return socksReply(client, socksRepOK)
	}

	rerr := s.tunnel(ctx, client, target(host, port), v, ev, ack)
	if rerr != nil && !acked {
		socksReply(client, socksFailureFor(rerr))
	}
	s.finish(ev, start, rerr)
}

// socksFailureFor maps a datapath failure onto the RFC's reply codes, which is
// the only channel SOCKS5 has for saying what went wrong.
func socksFailureFor(err error) byte {
	switch {
	case isRefused(err):
		return socksRepRefused
	case isUnreachable(err):
		return socksRepHostUnreach
	default:
		return socksRepGeneralFailure
	}
}

// socksGreet reads the method-selection message and answers it.
func socksGreet(rw io.ReadWriter) error {
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("version %d is not SOCKS5", hdr[0])
	}
	n := int(hdr[1])
	if n == 0 {
		_, _ = rw.Write([]byte{socks5Version, socksMethodNoneAccept})
		return fmt.Errorf("client offered no authentication methods")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(rw, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}
	for _, m := range methods {
		if m == socksMethodNone {
			_, err := rw.Write([]byte{socks5Version, socksMethodNone})
			return err
		}
	}
	_, _ = rw.Write([]byte{socks5Version, socksMethodNoneAccept})
	return fmt.Errorf("client offered no acceptable method")
}

// socksRequest reads the CONNECT request.
func socksRequest(r io.Reader) (cmd byte, host string, port int, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", 0, fmt.Errorf("read request: %w", err)
	}
	if hdr[0] != socks5Version {
		return 0, "", 0, fmt.Errorf("version %d is not SOCKS5", hdr[0])
	}
	cmd = hdr[1]

	switch hdr[3] {
	case socksATYPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return cmd, "", 0, fmt.Errorf("read IPv4 address: %w", err)
		}
		host = netip.AddrFrom4(a).String()
	case socksATYPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return cmd, "", 0, fmt.Errorf("read IPv6 address: %w", err)
		}
		host = netip.AddrFrom16(a).Unmap().String()
	case socksATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return cmd, "", 0, fmt.Errorf("read name length: %w", err)
		}
		if l[0] == 0 {
			return cmd, "", 0, fmt.Errorf("empty destination name")
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return cmd, "", 0, fmt.Errorf("read name: %w", err)
		}
		host = string(name)
	default:
		return cmd, "", 0, fmt.Errorf("address type %d is not supported", hdr[3])
	}

	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return cmd, "", 0, fmt.Errorf("read port: %w", err)
	}
	port = int(binary.BigEndian.Uint16(p[:]))
	if port == 0 {
		// Not an error here. RFC 1928 §7: a client that does not yet know the
		// address it will send datagrams from writes zeros in a UDP ASSOCIATE
		// request, and in practice every client does. It is still not a
		// destination for CONNECT, which serveSOCKS refuses below.
		return cmd, host, 0, nil
	}

	// Normalising here means a name and a literal reach policy in the same
	// spelling they would through CONNECT, so a rule cannot match one and miss
	// the other.
	h, pt, err := splitHostPort(hostPort(host, port), port)
	if err != nil {
		return cmd, "", 0, err
	}
	return cmd, h, pt, nil
}

func hostPort(host string, port int) string {
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, uint16(port)).String()
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// socksReply sends a reply with a zero bound address.
//
// RFC 1928 has BND.ADDR carry the address the proxy used, and every SOCKS5
// client in practice ignores it for CONNECT. Reporting 0.0.0.0:0 is the
// conventional answer and, unlike reporting the real upstream address, it does
// not tell the client which of several addresses a name resolved to — which is
// information the client deliberately delegated to us.
func socksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socks5Version, rep, 0x00, socksATYPv4, 0, 0, 0, 0, 0, 0})
	return err
}
