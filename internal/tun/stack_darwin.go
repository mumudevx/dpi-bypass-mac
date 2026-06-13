//go:build darwin

package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = tcpip.NICID(1)

// DialFunc dials the real destination. Implementations bind to the physical
// uplink (IP_BOUND_IF) so the upstream socket is not routed back into utun.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// InjectorFactory builds a RawInjector for a connection's 4-tuple (TUN-only
// fake-packet desync). It returns a cleanup func; on failure (e.g. no root) it
// returns a nil injector and the engine degrades to stream-level desync.
type InjectorFactory func(local, remote netip.AddrPort) (desync.RawInjector, func())

// Options configure the TUN server.
type Options struct {
	Device      *Device
	Engine      *desync.Engine
	NewInjector InjectorFactory
	Dial        DialFunc
	DesyncPorts map[int]bool
	Logf        func(string, ...any)
}

// Server runs a gVisor netstack over a utun device, transparently relaying TCP.
type Server struct {
	opt   Options
	stack *stack.Stack
}

// NewServer wires the netstack: promiscuous + spoofing so it accepts packets for
// any destination, a default route to the NIC, and a TCP forwarder.
func NewServer(opt Options) (*Server, error) {
	if opt.Device == nil {
		return nil, fmt.Errorf("tun: nil device")
	}
	if opt.Dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		opt.Dial = d.DialContext
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := newEndpoint(opt.Device.dev, uint32(opt.Device.mtu))
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create nic: %v", err)
	}
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	srv := &Server{opt: opt, stack: s}
	fwd := tcp.NewForwarder(s, 0, 2048, srv.handleForward)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return srv, nil
}

// Close stops the netstack and closes the device.
func (srv *Server) Close() {
	srv.stack.Close()
	_ = srv.opt.Device.Close()
}

func (srv *Server) handleForward(r *tcp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	client := gonet.NewTCPConn(&wq, ep)
	dstIP := net.IP(id.LocalAddress.AsSlice())
	dstPort := int(id.LocalPort)
	go srv.relay(client, dstIP, dstPort)
}

func (srv *Server) relay(client *gonet.TCPConn, dstIP net.IP, dstPort int) {
	defer client.Close()

	dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	upConn, err := srv.opt.Dial(dctx, "tcp", net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort)))
	cancel()
	if err != nil {
		srv.opt.Logf("tun dial %s:%d: %v", dstIP, dstPort, err)
		return
	}
	defer upConn.Close()
	tcpUp, _ := upConn.(*net.TCPConn)
	if tcpUp != nil {
		_ = tcpUp.SetNoDelay(true)
	}

	// First client payload (TLS ClientHello / HTTP request) → desync engine.
	buf := make([]byte, 16*1024)
	n, _ := client.Read(buf)
	if n > 0 {
		first := buf[:n]
		if tcpUp != nil && srv.opt.Engine != nil && srv.opt.DesyncPorts[dstPort] {
			if err := srv.applyDesync(tcpUp, first, dstPort); err != nil {
				srv.opt.Logf("tun apply %s:%d: %v", dstIP, dstPort, err)
				return
			}
		} else if _, err := upConn.Write(first); err != nil {
			return
		}
	}
	pipe(client, upConn)
}

// applyDesync wraps the upstream socket (with a per-connection RawInjector when
// available) and runs the desync engine on the first payload.
func (srv *Server) applyDesync(up *net.TCPConn, first []byte, dstPort int) error {
	var inj desync.RawInjector
	cleanup := func() {}
	if srv.opt.NewInjector != nil {
		local := toAddrPort(up.LocalAddr())
		remote := toAddrPort(up.RemoteAddr())
		if local.IsValid() && remote.IsValid() {
			inj, cleanup = srv.opt.NewInjector(local, remote)
		}
	}
	defer cleanup()
	return srv.opt.Engine.Apply(context.Background(), tunConn{up, inj}, first, dstPort)
}

func toAddrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort()
	}
	return netip.AddrPort{}
}

// pipe relays bytes in both directions until either side closes.
func pipe(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() { a.Close(); b.Close() }
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); once.Do(closeBoth); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); once.Do(closeBoth); done <- struct{}{} }()
	<-done
	<-done
}
