package tunfe

import (
	"fmt"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// ICMP port-unreachable, and why it is built by hand rather than emitted by the
// netstack.
//
// The netstack answers for whatever destination a packet names, so it never
// generates an unreachable for a port it is deliberately forwarding. When
// policy refuses a QUIC flow we therefore have to say "nothing is listening"
// ourselves, and the reply has to be a packet the CLIENT's kernel will match to
// its own socket: an ICMP error carries the offending datagram's IP header plus
// the first eight bytes of its transport header, and that is the only thing the
// receiver matches on.
//
// The point of refusing rather than dropping is the fallback it buys. Chrome
// and Firefox mark a path QUIC-broken on the first unreachable and retry over
// TCP within the same RTT, where the whole measured TCP ladder applies. A drop
// costs the user a QUIC connect timeout first, and a verbatim relay of UDP/443
// — what the previous implementation did — is strictly worse than proxy mode,
// which forces the TCP fallback by accident.

const (
	// icmpv4MinPayload is the "IP header plus 8 bytes" RFC 792 requires. We
	// send exactly that: it is what every receiver matches on, and more only
	// costs bytes.
	icmpv4OrigBytes = header.UDPMinimumSize
	// defaultHopLimit matches net.inet.ip.ttl on the development machine
	// (verified 2026-09-02). It is the TTL of a packet we synthesise, and a
	// receiver never checks it on an ICMP error.
	defaultHopLimit = 64
)

// portUnreachable builds the ICMP error announcing that dst is not listening
// for the datagram src sent it.
//
// src is the client that sent the datagram and dst is where it was addressed:
// the ICMP travels the other way, from dst to src, quoting the original.
// payloadLen is the length of the refused datagram's UDP payload, which appears
// only in the quoted UDP length field.
func portUnreachable(src, dst netip.AddrPort, payloadLen int) ([]byte, error) {
	switch {
	case src.Addr().Is4() && dst.Addr().Is4():
		return portUnreachableV4(src, dst, payloadLen), nil
	case src.Addr().Is6() && dst.Addr().Is6():
		return portUnreachableV6(src, dst, payloadLen), nil
	default:
		return nil, fmt.Errorf("tunfe: cannot build an ICMP error between %s and %s: mixed address families", src, dst)
	}
}

// portUnreachableV4 is RFC 792's destination unreachable / port unreachable.
func portUnreachableV4(src, dst netip.AddrPort, payloadLen int) []byte {
	orig := quotedIPv4(src, dst, payloadLen)

	total := header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(orig)
	pkt := make([]byte, total)

	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         defaultHopLimit,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpipAddr(dst.Addr()),
		DstAddr:     tcpipAddr(src.Addr()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	icmp := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4DstUnreachable)
	icmp.SetCode(header.ICMPv4PortUnreachable)
	copy(pkt[header.IPv4MinimumSize+header.ICMPv4MinimumSize:], orig)
	icmp.SetChecksum(0)
	icmp.SetChecksum(header.ICMPv4Checksum(icmp, 0))
	return pkt
}

// portUnreachableV6 is RFC 4443's destination unreachable / port unreachable.
// Its checksum covers an IPv6 pseudo-header, so unlike ICMPv4 it cannot be
// computed without the addresses.
func portUnreachableV6(src, dst netip.AddrPort, payloadLen int) []byte {
	orig := quotedIPv6(src, dst, payloadLen)

	icmpLen := header.ICMPv6DstUnreachableMinimumSize + len(orig)
	pkt := make([]byte, header.IPv6MinimumSize+icmpLen)

	srcAddr, dstAddr := tcpipAddr(dst.Addr()), tcpipAddr(src.Addr())
	ip := header.IPv6(pkt)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(icmpLen),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          defaultHopLimit,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})

	icmp := header.ICMPv6(pkt[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6DstUnreachable)
	icmp.SetCode(header.ICMPv6PortUnreachable)
	copy(pkt[header.IPv6MinimumSize+header.ICMPv6DstUnreachableMinimumSize:], orig)
	icmp.SetChecksum(0)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    srcAddr,
		Dst:    dstAddr,
	}))
	return pkt
}

// quotedIPv4 rebuilds the datagram being refused: its IPv4 header and the first
// eight bytes of its UDP header. We no longer hold the original packet — the
// forwarder handed us a session, not bytes — but every field a receiver matches
// on is in the session's own four-tuple, and the fields that are not (ID, TTL)
// are matched by nobody.
func quotedIPv4(src, dst netip.AddrPort, payloadLen int) []byte {
	total := header.IPv4MinimumSize + header.UDPMinimumSize + payloadLen
	b := make([]byte, header.IPv4MinimumSize+icmpv4OrigBytes)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         defaultHopLimit,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpipAddr(src.Addr()),
		DstAddr:     tcpipAddr(dst.Addr()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp := header.UDP(b[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + payloadLen),
	})
	return b
}

// quotedIPv6 is the same for IPv6.
func quotedIPv6(src, dst netip.AddrPort, payloadLen int) []byte {
	b := make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize)
	ip := header.IPv6(b)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize + payloadLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          defaultHopLimit,
		SrcAddr:           tcpipAddr(src.Addr()),
		DstAddr:           tcpipAddr(dst.Addr()),
	})
	udp := header.UDP(b[header.IPv6MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + payloadLen),
	})
	return b
}

// tcpipAddr converts an address for the header encoders.
func tcpipAddr(a netip.Addr) tcpip.Address {
	a = a.Unmap()
	return tcpip.AddrFromSlice(a.AsSlice())
}

// refuse writes an ICMP port-unreachable for a refused datagram straight to the
// device.
//
// It goes to the device rather than through the netstack because the netstack
// has no route to a source address it does not own and would drop it; the
// packet is fully formed here, and the endpoint applies the same offset
// contract and the same counters every other outbound packet gets.
func (s *Server) refuse(src, dst netip.AddrPort, payloadLen int) error {
	pkt, err := portUnreachable(src, dst, payloadLen)
	if err != nil {
		return err
	}
	if err := s.ep.writeRaw(pkt); err != nil {
		return err
	}
	s.refused.Add(1)
	return nil
}
