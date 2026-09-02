package testnet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// Packet generation for pipeLink, the in-memory TUN device the gVisor stack runs
// on in tests.
//
// These are built by hand rather than with gvisor's own header package on
// purpose. A test that constructs its input with the same library the code under
// test parses it with proves only that the library is self-consistent; if
// gvisor's checksum helper and gvisor's checksum validator ever disagree with
// the wire, both sides move together and the test never notices. Everything here
// is written from RFC 791, 793, 768 and 8200 directly, and the package's own
// tests validate it against gvisor's parser as an independent check.

const (
	ipProtoTCP = 6
	ipProtoUDP = 17

	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	tcpHeaderLen  = 20
	udpHeaderLen  = 8

	// TCPFlagSYN and friends are the control bits of RFC 793 §3.1.
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
)

// DefaultTTL is the hop limit stamped on generated packets. It matches the
// macOS default (net.inet.ip.ttl = 64) so a TTL-sensitive path under test sees a
// realistic starting value.
const DefaultTTL = 64

// TCPSYN builds a SYN segment from src to dst. Both addresses must be the same
// family.
func TCPSYN(src, dst netip.AddrPort, seq uint32) ([]byte, error) {
	return TCPSegment(src, dst, seq, 0, TCPFlagSYN, nil)
}

// TCPSegment builds a TCP segment with an arbitrary flag set and payload.
func TCPSegment(src, dst netip.AddrPort, seq, ack uint32, flags uint8, payload []byte) ([]byte, error) {
	if err := sameFamily(src, dst); err != nil {
		return nil, err
	}
	tcp := make([]byte, tcpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (tcpHeaderLen / 4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	copy(tcp[tcpHeaderLen:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(src.Addr(), dst.Addr(), ipProtoTCP, tcp))
	return encapsulate(src.Addr(), dst.Addr(), ipProtoTCP, tcp)
}

// UDP builds a UDP datagram carrying payload.
func UDP(src, dst netip.AddrPort, payload []byte) ([]byte, error) {
	if err := sameFamily(src, dst); err != nil {
		return nil, err
	}
	udp := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[udpHeaderLen:], payload)
	sum := transportChecksum(src.Addr(), dst.Addr(), ipProtoUDP, udp)
	if sum == 0 {
		// RFC 768: a computed checksum of zero is transmitted as all ones,
		// because zero means "no checksum" in IPv4 and is illegal in IPv6.
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return encapsulate(src.Addr(), dst.Addr(), ipProtoUDP, udp)
}

// DNSQuery builds a UDP datagram carrying a minimal DNS A query for name. It is
// the datagram a TUN front end's port-53 handler must answer in-process.
func DNSQuery(src, dst netip.AddrPort, id uint16, name string) ([]byte, error) {
	q, err := dnsQuestion(id, name)
	if err != nil {
		return nil, err
	}
	return UDP(src, dst, q)
}

func dnsQuestion(id uint16, name string) ([]byte, error) {
	var out []byte
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // one question
	out = append(out, hdr[:]...)

	for label := range splitLabels(strings.TrimSuffix(name, ".")) {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("testnet: bad DNS label %q in %q", label, name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0x00, 0x00, 0x01, 0x00, 0x01) // root, QTYPE=A, QCLASS=IN
	return out, nil
}

func splitLabels(name string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for len(name) > 0 {
			i := 0
			for i < len(name) && name[i] != '.' {
				i++
			}
			if !yield(name[:i]) {
				return
			}
			if i == len(name) {
				return
			}
			name = name[i+1:]
		}
	}
}

func sameFamily(src, dst netip.AddrPort) error {
	if !src.IsValid() || !dst.IsValid() {
		return fmt.Errorf("testnet: invalid address pair %v -> %v", src, dst)
	}
	if src.Addr().Is4() != dst.Addr().Is4() {
		return fmt.Errorf("testnet: mixed address families %v -> %v", src, dst)
	}
	return nil
}

// encapsulate wraps a transport-layer payload in an IPv4 or IPv6 header.
func encapsulate(src, dst netip.Addr, proto uint8, payload []byte) ([]byte, error) {
	if src.Is4() {
		return ipv4(src, dst, proto, payload), nil
	}
	if !src.Is6() {
		return nil, fmt.Errorf("testnet: address %v is neither v4 nor v6", src)
	}
	return ipv6(src, dst, proto, payload), nil
}

func ipv4(src, dst netip.Addr, proto uint8, payload []byte) []byte {
	out := make([]byte, ipv4HeaderLen+len(payload))
	out[0] = 0x45 // version 4, 5-word header
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint16(out[6:8], 0x4000) // don't fragment
	out[8] = DefaultTTL
	out[9] = proto
	s, d := src.As4(), dst.As4()
	copy(out[12:16], s[:])
	copy(out[16:20], d[:])
	binary.BigEndian.PutUint16(out[10:12], onesComplement(sum(out[:ipv4HeaderLen])))
	copy(out[ipv4HeaderLen:], payload)
	return out
}

func ipv6(src, dst netip.Addr, proto uint8, payload []byte) []byte {
	out := make([]byte, ipv6HeaderLen+len(payload))
	out[0] = 0x60 // version 6, no traffic class
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	out[6] = proto
	out[7] = DefaultTTL
	s, d := src.As16(), dst.As16()
	copy(out[8:24], s[:])
	copy(out[24:40], d[:])
	copy(out[ipv6HeaderLen:], payload)
	return out
}

// transportChecksum computes the RFC 1071 checksum over the pseudo-header and
// the transport segment. The segment's own checksum field must be zero.
func transportChecksum(src, dst netip.Addr, proto uint8, seg []byte) uint16 {
	var acc uint32
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		acc += sum(s[:]) + sum(d[:])
	} else {
		s, d := src.As16(), dst.As16()
		acc += sum(s[:]) + sum(d[:])
	}
	var tail [8]byte
	binary.BigEndian.PutUint32(tail[0:4], uint32(len(seg)))
	tail[7] = proto
	acc += sum(tail[:])
	acc += sum(seg)
	return onesComplement(acc)
}

// sum accumulates 16-bit big-endian words, padding an odd tail with a zero byte.
func sum(b []byte) uint32 {
	var acc uint32
	for i := 0; i+1 < len(b); i += 2 {
		acc += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		acc += uint32(b[len(b)-1]) << 8
	}
	return acc
}

func onesComplement(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// Verify recomputes the checksums of a generated packet and reports whether they
// hold, so a test can assert the generator itself is not the bug.
func Verify(pkt []byte) error {
	switch {
	case len(pkt) >= ipv4HeaderLen && pkt[0]>>4 == 4:
		if got := sumFold(sum(pkt[:ipv4HeaderLen])); got != 0xffff {
			return fmt.Errorf("testnet: IPv4 header checksum is wrong (folds to %#04x)", got)
		}
		src, _ := netip.AddrFromSlice(pkt[12:16])
		dst, _ := netip.AddrFromSlice(pkt[16:20])
		return verifyTransport(src, dst, pkt[9], pkt[ipv4HeaderLen:])
	case len(pkt) >= ipv6HeaderLen && pkt[0]>>4 == 6:
		src, _ := netip.AddrFromSlice(pkt[8:24])
		dst, _ := netip.AddrFromSlice(pkt[24:40])
		return verifyTransport(src, dst, pkt[6], pkt[ipv6HeaderLen:])
	}
	return fmt.Errorf("testnet: %d bytes are not an IP packet", len(pkt))
}

func verifyTransport(src, dst netip.Addr, proto uint8, seg []byte) error {
	switch proto {
	case ipProtoTCP, ipProtoUDP:
	default:
		return fmt.Errorf("testnet: unexpected protocol %d", proto)
	}
	var acc uint32
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		acc += sum(s[:]) + sum(d[:])
	} else {
		s, d := src.As16(), dst.As16()
		acc += sum(s[:]) + sum(d[:])
	}
	var tail [8]byte
	binary.BigEndian.PutUint32(tail[0:4], uint32(len(seg)))
	tail[7] = proto
	acc += sum(tail[:]) + sum(seg)
	if got := sumFold(acc); got != 0xffff {
		return fmt.Errorf("testnet: transport checksum is wrong (folds to %#04x)", got)
	}
	return nil
}

func sumFold(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return uint16(acc)
}
