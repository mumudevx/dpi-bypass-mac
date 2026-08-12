//go:build darwin

package tun

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// dnsPort is served locally rather than relayed, so queries ride the profile's
	// encrypted resolver chain instead of reaching a poisoned upstream.
	dnsPort = 53

	// defaultUDPIdle reaps a session after this long with no traffic in either
	// direction. UDP has no FIN, so without a reaper every flow would leak two
	// goroutines and a socket for the life of the process.
	defaultUDPIdle = 60 * time.Second

	// maxDatagram bounds a single relayed datagram. Larger than anything a
	// 1500-byte-MTU link delivers, with room for a reassembled jumbo DNS reply.
	maxDatagram = 64 * 1024

	dnsExchangeTimeout = 8 * time.Second
	udpDialTimeout     = 10 * time.Second
)

// handleUDPForward accepts a UDP session from the netstack and serves it in its
// own goroutine. Without this the split-default route black-holes every
// datagram: the routes pull all traffic into the utun, but only TCP had a
// handler, so DNS, QUIC and voice/WebRTC silently died.
func (srv *Server) handleUDPForward(r *udp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		srv.logf("tun udp endpoint %v:%d: %v", id.LocalAddress, id.LocalPort, terr)
		return
	}
	client := gonet.NewUDPConn(&wq, ep)
	dstIP := net.IP(id.LocalAddress.AsSlice())
	dstPort := int(id.LocalPort)
	go srv.serveUDP(client, dstIP, dstPort)
}

// serveUDP handles one UDP session: DNS is answered locally over the encrypted
// resolver chain, everything else is relayed to the real destination.
func (srv *Server) serveUDP(client net.Conn, dstIP net.IP, dstPort int) {
	defer client.Close()
	if dstPort == dnsPort && srv.opt.DNSExchange != nil {
		srv.serveDNS(client, dstIP)
		return
	}
	srv.relayUDP(client, dstIP, dstPort)
}

// serveDNS answers queries on this session from the resolver chain. Relaying
// them instead would hand the ISP's resolver back the queries DoH exists to
// hide, so the whole DNS-poisoning defence would be lost in TUN mode.
func (srv *Server) serveDNS(client net.Conn, dstIP net.IP) {
	idle := srv.udpIdle()
	buf := make([]byte, maxDatagram)
	for {
		_ = client.SetReadDeadline(time.Now().Add(idle))
		n, err := client.Read(buf)
		if n > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), dnsExchangeTimeout)
			reply, xerr := srv.opt.DNSExchange(ctx, buf[:n])
			cancel()
			if xerr != nil {
				srv.logf("tun dns via %s: %v", dstIP, xerr)
				return
			}
			_ = client.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := client.Write(reply); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// relayUDP pipes a session to the real destination through the bound dialer.
func (srv *Server) relayUDP(client net.Conn, dstIP net.IP, dstPort int) {
	ctx, cancel := context.WithTimeout(context.Background(), udpDialTimeout)
	up, err := srv.opt.Dial(ctx, "udp", net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort)))
	cancel()
	if err != nil {
		srv.logf("tun udp dial %s:%d: %v", dstIP, dstPort, err)
		return
	}
	defer up.Close()

	idle := srv.udpIdle()
	var once sync.Once
	closeBoth := func() { client.Close(); up.Close() }
	done := make(chan struct{}, 2)
	go func() { copyDatagrams(up, client, idle); once.Do(closeBoth); done <- struct{}{} }()
	go func() { copyDatagrams(client, up, idle); once.Do(closeBoth); done <- struct{}{} }()
	<-done
	<-done
}

// copyDatagrams relays src → dst one datagram at a time, refreshing the idle
// deadline on every packet. io.Copy is wrong here: it re-frames a byte stream,
// and UDP has no stream — a short read would truncate a datagram and a buffered
// write would merge two of them into one.
func copyDatagrams(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, maxDatagram)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (srv *Server) udpIdle() time.Duration {
	if srv.opt.UDPIdle > 0 {
		return srv.opt.UDPIdle
	}
	return defaultUDPIdle
}

func (srv *Server) logf(format string, args ...any) {
	if srv.opt.Logf != nil {
		srv.opt.Logf(format, args...)
	}
}
