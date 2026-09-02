package testnet

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// The assertions here parse the hand-built packets with gvisor's own header
// package — the parser the TUN front end will actually feed. Generating with one
// implementation and validating with another is the only way a checksum bug
// cannot hide: if both sides shared a helper, they would agree while the wire
// disagreed.

func TestTCPSYNv4ParsesInGvisor(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.2:51234")
	dst := netip.MustParseAddrPort("162.159.128.233:443")

	pkt, err := TCPSYN(src, dst, 0xdeadbeef)
	if err != nil {
		t.Fatalf("TCPSYN: %v", err)
	}
	if err := Verify(pkt); err != nil {
		t.Fatalf("self-check: %v", err)
	}

	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) {
		t.Fatal("gvisor rejects the IPv4 header as invalid")
	}
	if !ip.IsChecksumValid() {
		t.Fatal("gvisor rejects the IPv4 header checksum")
	}
	if ip.Protocol() != uint8(header.TCPProtocolNumber) {
		t.Fatalf("protocol = %d", ip.Protocol())
	}
	if ip.TTL() != DefaultTTL {
		t.Errorf("TTL = %d, want the macOS default %d", ip.TTL(), DefaultTTL)
	}
	if ip.SourceAddress().String() != "10.0.0.2" || ip.DestinationAddress().String() != "162.159.128.233" {
		t.Fatalf("addresses = %v -> %v", ip.SourceAddress(), ip.DestinationAddress())
	}

	tcp := header.TCP(ip.Payload())
	if tcp.SourcePort() != 51234 || tcp.DestinationPort() != 443 {
		t.Fatalf("ports = %d -> %d", tcp.SourcePort(), tcp.DestinationPort())
	}
	if tcp.Flags() != header.TCPFlagSyn {
		t.Fatalf("flags = %v, want SYN alone", tcp.Flags())
	}
	if tcp.SequenceNumber() != 0xdeadbeef {
		t.Fatalf("seq = %#x", tcp.SequenceNumber())
	}
	if !tcp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(),
		checksum.Checksum(tcp.Payload(), 0), uint16(len(tcp.Payload()))) {
		t.Fatal("gvisor rejects the TCP checksum")
	}
}

func TestTCPSegmentv6WithPayload(t *testing.T) {
	src := netip.MustParseAddrPort("[2001:db8::2]:51234")
	dst := netip.MustParseAddrPort("[2606:4700::1]:443")
	payload := []byte("hello there, this is a payload of odd length")

	pkt, err := TCPSegment(src, dst, 1, 2, TCPFlagPSH|TCPFlagACK, payload)
	if err != nil {
		t.Fatalf("TCPSegment: %v", err)
	}
	if err := Verify(pkt); err != nil {
		t.Fatalf("self-check: %v", err)
	}

	ip := header.IPv6(pkt)
	if ip.NextHeader() != uint8(header.TCPProtocolNumber) {
		t.Fatalf("next header = %d", ip.NextHeader())
	}
	if int(ip.PayloadLength()) != len(pkt)-40 {
		t.Fatalf("payload length = %d, packet is %d", ip.PayloadLength(), len(pkt))
	}
	tcp := header.TCP(ip.Payload())
	if string(tcp.Payload()) != string(payload) {
		t.Fatalf("payload = %q", tcp.Payload())
	}
	if tcp.Flags() != header.TCPFlagPsh|header.TCPFlagAck {
		t.Fatalf("flags = %v", tcp.Flags())
	}
	if !tcp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(),
		checksum.Checksum(tcp.Payload(), 0), uint16(len(tcp.Payload()))) {
		t.Fatal("gvisor rejects the TCP checksum")
	}
}

func TestUDPv4AndV6(t *testing.T) {
	cases := []struct {
		name     string
		src, dst netip.AddrPort
		v6       bool
	}{
		{"v4", netip.MustParseAddrPort("10.0.0.2:5353"), netip.MustParseAddrPort("8.8.8.8:53"), false},
		{"v6", netip.MustParseAddrPort("[2001:db8::2]:5353"), netip.MustParseAddrPort("[2001:4860:4860::8888]:53"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := UDP(tc.src, tc.dst, []byte("odd"))
			if err != nil {
				t.Fatalf("UDP: %v", err)
			}
			if err := Verify(pkt); err != nil {
				t.Fatalf("self-check: %v", err)
			}
			var udp header.UDP
			var src, dst tcpip.Address
			if tc.v6 {
				ip := header.IPv6(pkt)
				udp, src, dst = header.UDP(ip.Payload()), ip.SourceAddress(), ip.DestinationAddress()
			} else {
				ip := header.IPv4(pkt)
				if !ip.IsChecksumValid() {
					t.Fatal("IPv4 checksum rejected")
				}
				udp, src, dst = header.UDP(ip.Payload()), ip.SourceAddress(), ip.DestinationAddress()
			}
			if udp.DestinationPort() != 53 {
				t.Fatalf("dst port = %d", udp.DestinationPort())
			}
			if int(udp.Length()) != len(udp) {
				t.Fatalf("length field = %d, actual %d", udp.Length(), len(udp))
			}
			if string(udp.Payload()) != "odd" {
				t.Fatalf("payload = %q", udp.Payload())
			}
			if !udp.IsChecksumValid(src, dst, checksum.Checksum(udp.Payload(), 0)) {
				t.Fatal("gvisor rejects the UDP checksum")
			}
		})
	}
}

// TestDNSQueryIsWellFormed covers the datagram a TUN front end must answer
// in-process on port 53.
func TestDNSQueryIsWellFormed(t *testing.T) {
	pkt, err := DNSQuery(
		netip.MustParseAddrPort("10.0.0.2:5353"),
		netip.MustParseAddrPort("10.0.0.1:53"),
		0x1234, "cdn.discordapp.com")
	if err != nil {
		t.Fatalf("DNSQuery: %v", err)
	}
	if err := Verify(pkt); err != nil {
		t.Fatalf("self-check: %v", err)
	}
	q := header.UDP(header.IPv4(pkt).Payload()).Payload()
	if len(q) < 12 {
		t.Fatalf("DNS message is %d bytes", len(q))
	}
	if q[0] != 0x12 || q[1] != 0x34 {
		t.Fatalf("transaction ID = %#x%#x", q[0], q[1])
	}
	if q[5] != 1 {
		t.Fatalf("QDCOUNT = %d", q[5])
	}
	// 3"cdn" 10"discordapp" 3"com" 0
	want := "\x03cdn\ndiscordapp\x03com\x00\x00\x01\x00\x01"
	if got := string(q[12:]); got != want {
		t.Fatalf("question = %q, want %q", got, want)
	}
}

func TestPacketgenRejectsBadInput(t *testing.T) {
	v4 := netip.MustParseAddrPort("10.0.0.2:1")
	v6 := netip.MustParseAddrPort("[2001:db8::2]:1")

	if _, err := TCPSYN(v4, v6, 0); err == nil {
		t.Error("mixed address families were accepted")
	}
	if _, err := UDP(netip.AddrPort{}, v4, nil); err == nil {
		t.Error("an invalid source was accepted")
	}
	if _, err := DNSQuery(v4, v4, 1, "bad..name"); err == nil {
		t.Error("an empty DNS label was accepted")
	}
	if err := Verify([]byte{0x00}); err == nil {
		t.Error("Verify accepted a one-byte packet")
	}
	if err := Verify(make([]byte, 64)); err == nil {
		t.Error("Verify accepted a zeroed buffer")
	}
}

// TestVerifyCatchesCorruption proves the self-check is load-bearing rather than
// decorative: flip a byte and it must complain.
func TestVerifyCatchesCorruption(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.2:51234")
	dst := netip.MustParseAddrPort("1.1.1.1:443")

	pkt, err := TCPSYN(src, dst, 1)
	if err != nil {
		t.Fatalf("TCPSYN: %v", err)
	}
	bad := append([]byte(nil), pkt...)
	bad[16] ^= 0x01 // a destination-address byte: breaks the IP header checksum
	if err := Verify(bad); err == nil {
		t.Error("Verify accepted a corrupted IPv4 header")
	}

	bad = append([]byte(nil), pkt...)
	bad[ipv4HeaderLen+4] ^= 0x01 // a sequence-number byte: breaks the TCP checksum
	if err := Verify(bad); err == nil {
		t.Error("Verify accepted a corrupted TCP segment")
	}

	v6, err := TCPSYN(netip.MustParseAddrPort("[2001:db8::2]:1"), netip.MustParseAddrPort("[2001:db8::3]:2"), 1)
	if err != nil {
		t.Fatalf("TCPSYN v6: %v", err)
	}
	v6[ipv6HeaderLen+4] ^= 0x01
	if err := Verify(v6); err == nil {
		t.Error("Verify accepted a corrupted IPv6 segment")
	}
}

// TestUDPZeroChecksumIsTransmittedAsOnes pins RFC 768's special case. A zero
// checksum means "none" in IPv4 and is illegal in IPv6, so a generator that
// emitted it would produce packets gVisor drops for reasons the test author
// would spend an afternoon on.
func TestUDPZeroChecksumIsTransmittedAsOnes(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.2:5353")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	for i := range 512 {
		pkt, err := UDP(src, dst, []byte{byte(i), byte(i >> 8)})
		if err != nil {
			t.Fatalf("UDP: %v", err)
		}
		udp := header.UDP(header.IPv4(pkt).Payload())
		if udp.Checksum() == 0 {
			t.Fatalf("payload %d produced a zero checksum on the wire", i)
		}
		if err := Verify(pkt); err != nil {
			t.Fatalf("payload %d: %v", i, err)
		}
	}
}
