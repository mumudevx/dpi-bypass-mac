//go:build darwin

package tun

import (
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// linkOffset is the space wireguard/tun reserves before each IP packet for the
// macOS 4-byte address-family prefix (handled inside the library).
const linkOffset = 4

// endpoint bridges a wireguard/tun Device to a gVisor LinkEndpoint: it pumps IP
// packets from the device into the netstack and writes netstack output back.
type endpoint struct {
	dev tun.Device
	mtu uint32

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
	wg         sync.WaitGroup
	closeOnce  sync.Once
	onClose    func()
}

func newEndpoint(dev tun.Device, mtu uint32) *endpoint {
	return &endpoint{dev: dev, mtu: mtu}
}

func (e *endpoint) MTU() uint32                                  { return e.mtu }
func (e *endpoint) SetMTU(m uint32)                              { e.mtu = m }
func (e *endpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *endpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *endpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }
func (e *endpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *endpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *endpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *endpoint) SetOnCloseAction(f func())                    { e.onClose = f }
func (e *endpoint) Wait()                                        { e.wg.Wait() }

func (e *endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// Attach starts the device read loop once the stack provides a dispatcher.
func (e *endpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = d
	e.mu.Unlock()
	if d != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.readLoop()
		}()
	}
}

func (e *endpoint) Close() {
	e.closeOnce.Do(func() {
		if e.onClose != nil {
			e.onClose()
		}
		_ = e.dev.Close()
	})
}

func (e *endpoint) dispatch() stack.NetworkDispatcher {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher
}

func (e *endpoint) readLoop() {
	batch := e.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, int(e.mtu)+linkOffset+16)
	}
	for {
		n, err := e.dev.Read(bufs, sizes, linkOffset)
		if err != nil {
			return
		}
		d := e.dispatch()
		if d == nil {
			return
		}
		for i := 0; i < n; i++ {
			sz := sizes[i]
			if sz == 0 {
				continue
			}
			pktBytes := bufs[i][linkOffset : linkOffset+sz]
			var proto tcpip.NetworkProtocolNumber
			switch pktBytes[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pktBytes),
			})
			d.DeliverNetworkPacket(proto, pb)
			pb.DecRef()
		}
	}
}

// WritePackets serialises each netstack packet and writes it to the utun device.
func (e *endpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	written := 0
	for _, pb := range list.AsSlice() {
		ipPkt := pb.ToView().AsSlice()
		out := make([]byte, linkOffset+len(ipPkt))
		copy(out[linkOffset:], ipPkt)
		if _, err := e.dev.Write([][]byte{out}, linkOffset); err != nil {
			return written, &tcpip.ErrAborted{}
		}
		written++
	}
	return written, nil
}
