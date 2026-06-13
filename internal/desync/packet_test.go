package desync

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildIPv4TCP(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.50:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	payload := []byte("hello-decoy")
	seg := buildIPv4TCP(segParams{
		src: src, dst: dst, seq: 0x11223344, ack: 0x55667788,
		flags: tcpFlagPSH | tcpFlagACK, ttl: 6, payload: payload,
	})

	if len(seg) != 20+20+len(payload) {
		t.Fatalf("len = %d", len(seg))
	}
	if seg[0] != 0x45 {
		t.Fatalf("version/IHL = %#x", seg[0])
	}
	if int(binary.BigEndian.Uint16(seg[2:4])) != len(seg) {
		t.Fatal("bad total length")
	}
	if seg[8] != 6 {
		t.Fatalf("ttl = %d, want 6", seg[8])
	}
	if seg[9] != 6 {
		t.Fatal("protocol not TCP")
	}
	// IP header checksum must validate (sum incl. checksum field == 0).
	if onesComplement(seg[0:20]) != 0 {
		t.Fatal("invalid IP checksum")
	}
	// Ports + seq in the TCP header.
	if binary.BigEndian.Uint16(seg[20:22]) != 54321 {
		t.Fatal("bad src port")
	}
	if binary.BigEndian.Uint16(seg[22:24]) != 443 {
		t.Fatal("bad dst port")
	}
	if binary.BigEndian.Uint32(seg[24:28]) != 0x11223344 {
		t.Fatal("bad seq")
	}
	// TCP checksum must validate over the pseudo-header + segment.
	src4 := src.Addr().As4()
	dst4 := dst.Addr().As4()
	if tcpChecksum(src4, dst4, seg[20:]) != 0 {
		t.Fatal("invalid TCP checksum")
	}
}

func TestBuildIPv4TCPBadChecksum(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.1:1234")
	dst := netip.MustParseAddrPort("10.0.0.2:443")
	good := buildIPv4TCP(segParams{src: src, dst: dst, seq: 1, flags: tcpFlagACK})
	bad := buildIPv4TCP(segParams{src: src, dst: dst, seq: 1, flags: tcpFlagACK, badChecksum: true})
	if string(good[36:38]) == string(bad[36:38]) {
		t.Fatal("badChecksum did not change the TCP checksum")
	}
	src4 := src.Addr().As4()
	dst4 := dst.Addr().As4()
	if tcpChecksum(src4, dst4, bad[20:]) == 0 {
		t.Fatal("bad checksum unexpectedly validates")
	}
}

func TestBuildDecoyClientHello(t *testing.T) {
	decoy := buildDecoyClientHello("www.google.com")
	sni, _, _, ok := parseClientHello(decoy)
	if !ok || sni != "www.google.com" {
		t.Fatalf("decoy SNI = %q ok=%v", sni, ok)
	}
}
