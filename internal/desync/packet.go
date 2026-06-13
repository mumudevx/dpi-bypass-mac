package desync

import (
	"encoding/binary"
	"net/netip"
)

// TCP flag bits used by the fake-packet emitters.
const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
)

// segParams describes a TCP/IPv4 segment to synthesise for a fake decoy.
type segParams struct {
	src, dst    netip.AddrPort
	seq, ack    uint32
	flags       uint8
	ttl         uint8
	window      uint16
	payload     []byte
	badChecksum bool // deliberately corrupt the TCP checksum (server drops it)
}

// buildIPv4TCP assembles a complete IPv4 + TCP segment in canonical network
// byte order with correct checksums (unless badChecksum is set). It is a pure
// function so it is fully unit-testable; the platform raw-socket layer applies
// any OS-specific fixups (e.g. macOS IP_HDRINCL byte-order quirks) at send time.
func buildIPv4TCP(p segParams) []byte {
	const ipHL, tcpHL = 20, 20
	total := ipHL + tcpHL + len(p.payload)
	b := make([]byte, total)

	// IPv4 header.
	b[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8] = p.ttl
	b[9] = 6 // protocol TCP
	src4 := p.src.Addr().As4()
	dst4 := p.dst.Addr().As4()
	copy(b[12:16], src4[:])
	copy(b[16:20], dst4[:])
	binary.BigEndian.PutUint16(b[10:12], onesComplement(b[0:20]))

	// TCP header.
	t := b[20:]
	binary.BigEndian.PutUint16(t[0:2], p.src.Port())
	binary.BigEndian.PutUint16(t[2:4], p.dst.Port())
	binary.BigEndian.PutUint32(t[4:8], p.seq)
	binary.BigEndian.PutUint32(t[8:12], p.ack)
	t[12] = (tcpHL / 4) << 4 // data offset, no options
	t[13] = p.flags
	if p.window == 0 {
		p.window = 65535
	}
	binary.BigEndian.PutUint16(t[14:16], p.window)
	copy(t[20:], p.payload)

	ck := tcpChecksum(src4, dst4, t)
	if p.badChecksum {
		ck ^= 0xffff // flip to an invalid checksum
	}
	binary.BigEndian.PutUint16(t[16:18], ck)
	return b
}

// onesComplement computes the 16-bit one's-complement checksum of b.
func onesComplement(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the IPv4 pseudo-header + segment.
// The segment's checksum field (t[16:18]) must be zero on entry.
func tcpChecksum(src, dst [4]byte, t []byte) uint16 {
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += 6 // protocol
	sum += uint32(len(t))
	for i := 0; i+1 < len(t); i += 2 {
		sum += uint32(t[i])<<8 | uint32(t[i+1])
	}
	if len(t)%2 == 1 {
		sum += uint32(t[len(t)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildDecoyClientHello builds a minimal TLS ClientHello record carrying a
// benign SNI, used as a fake packet the DPI inspects (and whitelists) while the
// real request follows.
func buildDecoyClientHello(sni string) []byte {
	host := []byte(sni)

	// server_name extension body.
	sniList := make([]byte, 0, 5+len(host))
	sniList = append(sniList, 0x00) // host_name
	sniList = appendU16(sniList, uint16(len(host)))
	sniList = append(sniList, host...)
	extData := appendU16(nil, uint16(len(sniList)))
	extData = append(extData, sniList...)
	ext := []byte{0x00, 0x00} // server_name
	ext = appendU16(ext, uint16(len(extData)))
	ext = append(ext, extData...)

	// handshake body.
	hs := []byte{0x03, 0x03} // client version
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0x00)                   // session id len
	hs = append(hs, 0x00, 0x02, 0x00, 0x2f) // cipher suites
	hs = append(hs, 0x01, 0x00)             // compression
	hs = appendU16(hs, uint16(len(ext)))    // extensions length
	hs = append(hs, ext...)

	handshake := []byte{handshakeTypeClientHello}
	handshake = append(handshake, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	handshake = append(handshake, hs...)

	rec := []byte{recordTypeHandshake, 0x03, 0x01}
	rec = appendU16(rec, uint16(len(handshake)))
	rec = append(rec, handshake...)
	return rec
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
