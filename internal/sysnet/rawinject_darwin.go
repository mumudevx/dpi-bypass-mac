//go:build darwin

package sysnet

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// RawInjector sends fully-crafted IPv4+TCP segments through a raw socket, used
// by the fake-packet desync emitters in TUN mode. Requires root. It satisfies
// desync.RawInjector structurally (InjectSegment / Endpoints / BaseSeq).
type RawInjector struct {
	fd  int
	src netip.AddrPort
	dst netip.AddrPort
	seq uint32
}

// NewRawInjector opens a raw socket for crafting fake segments toward dst.
func NewRawInjector(src, dst netip.AddrPort, seq uint32) (*RawInjector, error) {
	if !dst.Addr().Is4() {
		return nil, fmt.Errorf("raw injector: IPv4 only")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw socket (needs root): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &RawInjector{fd: fd, src: src, dst: dst, seq: seq}, nil
}

// Endpoints returns the real connection's local and remote addresses.
func (r *RawInjector) Endpoints() (netip.AddrPort, netip.AddrPort) { return r.src, r.dst }

// BaseSeq returns the sequence base for crafted fakes.
func (r *RawInjector) BaseSeq() uint32 { return r.seq }

// InjectSegment sends a crafted IPv4+TCP segment, applying the macOS IP_HDRINCL
// byte-order fixup (ip_len and ip_off must be in host order on the send path).
func (r *RawInjector) InjectSegment(seg []byte) error {
	pkt := seg
	if len(seg) >= 8 {
		pkt = append([]byte(nil), seg...)
		pkt[2], pkt[3] = pkt[3], pkt[2]
		pkt[6], pkt[7] = pkt[7], pkt[6]
	}
	sa := &unix.SockaddrInet4{Port: int(r.dst.Port()), Addr: r.dst.Addr().As4()}
	return unix.Sendto(r.fd, pkt, 0, sa)
}

// Close releases the raw socket.
func (r *RawInjector) Close() error { return unix.Close(r.fd) }
