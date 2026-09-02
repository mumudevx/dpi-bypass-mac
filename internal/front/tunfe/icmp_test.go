package tunfe

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestPortUnreachableV4IsWellFormed checks the packet a browser has to
// understand: the outer header addressed back to the sender, and the quoted
// datagram that lets the receiver's kernel match the error to the right socket.
// Getting the quoted four-tuple backwards produces a packet that looks fine on
// the wire and is silently ignored by every receiver.
func TestPortUnreachableV4IsWellFormed(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddrPort("192.0.2.2:51000")
	dst := netip.MustParseAddrPort("192.0.2.10:443")

	pkt, err := portUnreachable(src, dst, 1200)
	if err != nil {
		t.Fatalf("portUnreachable: %v", err)
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) {
		t.Fatal("the outer IPv4 header is not valid")
	}
	if got := ip.CalculateChecksum(); got != 0xffff {
		t.Fatalf("outer IPv4 checksum does not verify (residual %#x)", got)
	}
	if ip.SourceAddress() != tcpipAddr(dst.Addr()) {
		t.Fatalf("outer source = %v, want the destination that is refusing: %v",
			ip.SourceAddress(), dst.Addr())
	}
	if ip.DestinationAddress() != tcpipAddr(src.Addr()) {
		t.Fatalf("outer destination = %v, want the sender %v", ip.DestinationAddress(), src.Addr())
	}
	if ip.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		t.Fatalf("outer protocol = %d, want ICMP", ip.Protocol())
	}

	icmp := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	if icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable {
		t.Fatalf("ICMP type/code = %d/%d, want 3/3 (port unreachable)", icmp.Type(), icmp.Code())
	}
	want := icmp.Checksum()
	icmp.SetChecksum(0)
	if got := header.ICMPv4Checksum(icmp, 0); got != want {
		t.Fatalf("ICMP checksum = %#x, recomputed %#x", want, got)
	}
	icmp.SetChecksum(want)

	// The quoted datagram travels the ORIGINAL direction.
	quoted := header.IPv4(icmp.Payload())
	if quoted.SourceAddress() != tcpipAddr(src.Addr()) || quoted.DestinationAddress() != tcpipAddr(dst.Addr()) {
		t.Fatalf("quoted datagram runs %v -> %v, want %v -> %v",
			quoted.SourceAddress(), quoted.DestinationAddress(), src.Addr(), dst.Addr())
	}
	if quoted.Protocol() != uint8(header.UDPProtocolNumber) {
		t.Fatalf("quoted protocol = %d, want UDP", quoted.Protocol())
	}
	if got, want := int(quoted.TotalLength()), header.IPv4MinimumSize+header.UDPMinimumSize+1200; got != want {
		t.Fatalf("quoted total length = %d, want %d", got, want)
	}
	udp := header.UDP(quoted[header.IPv4MinimumSize:])
	if udp.SourcePort() != src.Port() || udp.DestinationPort() != dst.Port() {
		t.Fatalf("quoted ports = %d -> %d, want %d -> %d",
			udp.SourcePort(), udp.DestinationPort(), src.Port(), dst.Port())
	}
	if got, want := int(udp.Length()), header.UDPMinimumSize+1200; got != want {
		t.Fatalf("quoted UDP length = %d, want %d", got, want)
	}
}

// TestPortUnreachableV6IsUnderstoodByAReceiver runs the IPv6 unreachable
// through a real receiver: the client netstack must match it to its own socket
// and report a refusal, which is the same thing a browser's kernel does.
func TestPortUnreachableV6IsUnderstoodByAReceiver(t *testing.T) {
	udp := &countingUDPDialer{}
	l := newLab(t, labOpts{udp: udp})

	client, err := l.dialUDP(netip.AddrPortFrom(originV6, 443))
	if err != nil {
		t.Fatalf("dial udp6: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(quicInitial(t, 48)); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	waitFor(t, 5*time.Second, "the IPv6 QUIC Initial to be refused", func() bool {
		return l.server.Stats().Refused > 0
	})
	if n := udp.count(); n != 0 {
		t.Fatalf("%d upstream socket(s) opened for a refused IPv6 QUIC flow", n)
	}

	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		buf := make([]byte, 64)
		if _, err := client.Read(buf); err != nil && !isTimeoutErr(err) {
			last = err
			break
		}
	}
	if last == nil {
		t.Fatal("the client socket never saw the ICMPv6 unreachable")
	}
	t.Logf("client observed %v", last)
}

// TestPortUnreachableRefusesMixedFamilies: an ICMP error between two families
// cannot be built, and saying so beats emitting a packet with a truncated or
// nonsensical address in it.
func TestPortUnreachableRefusesMixedFamilies(t *testing.T) {
	t.Parallel()
	v4 := netip.MustParseAddrPort("192.0.2.2:51000")
	v6 := netip.MustParseAddrPort("[2001:db8::10]:443")
	if _, err := portUnreachable(v4, v6, 10); err == nil {
		t.Fatal("built an ICMP error between an IPv4 sender and an IPv6 destination")
	}
	if _, err := portUnreachable(v6, v4, 10); err == nil {
		t.Fatal("built an ICMP error between an IPv6 sender and an IPv4 destination")
	}
}

// TestRefuseReportsAWriteFailure: refusal happens on the device, so a device
// that is gone must be reported rather than counted as a refusal that never
// left.
func TestRefuseReportsAWriteFailure(t *testing.T) {
	l := newLab(t, labOpts{noStart: true})
	_ = l.serverLink.Close()

	src := netip.AddrPortFrom(clientIP, 51000)
	dst := netip.AddrPortFrom(originIP, 443)
	if err := l.server.refuse(src, dst, 10); err == nil {
		t.Fatal("refuse reported success writing to a closed device")
	}
	if s := l.server.Stats(); s.Refused != 0 {
		t.Fatalf("Refused = %d after a failed write", s.Refused)
	}
}
