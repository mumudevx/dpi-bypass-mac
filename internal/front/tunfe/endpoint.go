package tunfe

import (
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/mumudevx/dpb/internal/flow"
)

// DefaultMTU is the utun MTU this tool configures. 1500 matches the physical
// uplink, so a full-sized ClientHello arrives in the same two segments TUN mode
// must reassemble anyway (docs/PLAN.md data path B step 1).
const DefaultMTU = 1500

// readSlack is the headroom past the MTU in each read buffer. A device may hand
// back slightly more than the configured MTU; a short buffer would be reported
// as a read error and tear the datapath down for nothing.
const readSlack = 64

// endpoint bridges a Link to gVisor's link layer.
//
// Three properties here are regressions from the previous tree, each of which
// shipped:
//
//  1. A read error is reported to the supervisor over a channel, never
//     swallowed. A bare `return` from the read loop is a permanent, total IPv4
//     blackout while the capture routes still point at a dead device, and it
//     has no symptom in any log.
//  2. Every PacketBuffer delivered inbound is DecRef'd, and every pooled View
//     taken outbound is Released. Both are counted, so a leak is a failing test
//     rather than a slow drift in RSS.
//  3. Read and Write use LinkOffset, and the Link implementations refuse an
//     offset below it, so the Darwin address-family prefix contract cannot be
//     violated silently.
type endpoint struct {
	link Link
	logf func(string, ...any)

	mtu atomic.Uint32

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher

	wg      sync.WaitGroup
	onClose func()
	closed  atomic.Bool

	// errs carries the read-loop's terminal error to whoever supervises the
	// datapath. It is buffered so the read loop never blocks on a supervisor
	// that has gone away, and a full channel drops rather than wedges.
	errs chan error

	// View accounting. viewsTaken counts pooled Views obtained from
	// PacketBuffer.ToView; viewsFreed counts the ones handed back. The
	// difference is the leak.
	viewsTaken atomic.Uint64
	viewsFreed atomic.Uint64
	pktsIn     atomic.Uint64
	pktsOut    atomic.Uint64
	readErrs   atomic.Uint64
}

var _ stack.LinkEndpoint = (*endpoint)(nil)

// newEndpoint wraps l. mtu is the value the stack will use; it need not equal
// the device MTU, but the shipped path passes the device's own.
func newEndpoint(l Link, mtu uint32, logf func(string, ...any)) *endpoint {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	e := &endpoint{link: l, logf: logf, errs: make(chan error, 4)}
	e.mtu.Store(mtu)
	return e
}

// Errors reports the read loop's terminal failure. At most one value is ever
// sent for one endpoint.
func (e *endpoint) Errors() <-chan error { return e.errs }

func (e *endpoint) MTU() uint32     { return e.mtu.Load() }
func (e *endpoint) SetMTU(m uint32) { e.mtu.Store(m) }

// MaxHeaderLength is zero: a utun carries bare IP packets with no link header.
// The 4-byte address-family prefix is the device's, not the packet's, and it is
// supplied by the write buffer's offset rather than reserved in the packet.
func (e *endpoint) MaxHeaderLength() uint16 { return 0 }

func (e *endpoint) LinkAddress() tcpip.LinkAddress { return "" }

// SetLinkAddress is a no-op: a point-to-point tunnel has no link layer, so
// there is no address to set and LinkAddress keeps reporting none. The
// assignment is what makes that deliberate ignoring visible to the coverage
// gate rather than an empty body nothing can distinguish from an unfinished
// one.
func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) { _ = addr }
func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// Capabilities is deliberately empty: with no CapabilityRXChecksumOffload or
// CapabilityTXChecksumOffload gVisor computes and validates every checksum
// itself, which is what a point-to-point tunnel with no hardware behind it
// requires.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }

// AddHeader is a no-op for the same reason: the only thing in front of an IP
// packet on this device is the 4-byte address-family prefix, and that belongs
// to the write buffer's offset rather than to the packet.
func (e *endpoint) AddHeader(pkt *stack.PacketBuffer) { _ = pkt }

// ParseHeader always succeeds: there is no link header to parse.
func (e *endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }
func (e *endpoint) SetOnCloseAction(f func())            { e.onClose = f }

// Wait blocks until the read loop has stopped. The stack calls it while
// removing a NIC, and Server.Close relies on it so that no goroutine is still
// reading a device the caller is about to close.
func (e *endpoint) Wait() { e.wg.Wait() }

func (e *endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// Attach starts the read loop once the stack hands over a dispatcher, and stops
// dispatching when it is detached with nil.
func (e *endpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	already := e.dispatcher != nil
	e.dispatcher = d
	e.mu.Unlock()
	if d == nil || already {
		return
	}
	e.wg.Add(1)
	flow.Safe("tunfe/endpoint.readLoop", e.logf, func() {
		defer e.wg.Done()
		e.readLoop()
	})
}

// Close is called by the stack when the NIC is removed.
func (e *endpoint) Close() {
	if e.closed.Swap(true) {
		return
	}
	if e.onClose != nil {
		e.onClose()
	}
}

func (e *endpoint) dispatch() stack.NetworkDispatcher {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher
}

// readLoop pumps packets from the device into the stack.
//
// It ends on three conditions, and only one of them is a failure: the endpoint
// was detached (shutdown), the link was closed (shutdown), or the device
// reported an error (failure, reported on Errors()). The previous
// implementation's `if err != nil { return }` conflated all three.
func (e *endpoint) readLoop() {
	batch := e.link.BatchSize()
	if batch < 1 {
		batch = 1
	}
	size := int(e.MTU()) + LinkOffset + readSlack
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}

	for {
		n, err := e.link.Read(bufs, sizes, LinkOffset)
		for i := 0; i < n && i < len(sizes); i++ {
			e.deliver(bufs[i][LinkOffset : LinkOffset+sizes[i]])
		}
		if err == nil {
			continue
		}
		if isClosedLinkErr(err) || e.closed.Load() {
			return
		}
		e.readErrs.Add(1)
		e.fail(fmt.Errorf("tunfe: read from the tunnel device: %w", err))
		return
	}
}

// deliver hands one IP packet to the stack.
func (e *endpoint) deliver(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	proto, ok := netProto(pkt)
	if !ok {
		// Not IPv4 or IPv6. A utun carries nothing else, so this is corruption
		// or a family we do not handle; dropping one packet is the whole cost.
		return
	}
	d := e.dispatch()
	if d == nil {
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	d.DeliverNetworkPacket(proto, pb)
	// gVisor's Views are pooled: without this the pool never gets the packet
	// back and the process grows for the life of the run.
	pb.DecRef()
	e.pktsIn.Add(1)
}

// WritePackets serialises each packet the stack produced and hands it to the
// device.
//
// The pooled View from ToView is Released on every path, including the error
// paths, which is the leak the previous implementation shipped.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	written := 0
	buf := make([]byte, 0, int(e.MTU())+LinkOffset+readSlack)
	for _, pb := range pkts.AsSlice() {
		v := pb.ToView()
		e.viewsTaken.Add(1)
		n := v.Size()
		if cap(buf) < LinkOffset+n {
			buf = make([]byte, LinkOffset+n)
		}
		out := buf[:LinkOffset+n]
		copy(out[LinkOffset:], v.AsSlice())
		v.Release()
		e.viewsFreed.Add(1)

		if _, err := e.link.Write([][]byte{out}, LinkOffset); err != nil {
			if isClosedLinkErr(err) {
				return written, &tcpip.ErrClosedForSend{}
			}
			e.fail(fmt.Errorf("tunfe: write to the tunnel device: %w", err))
			return written, &tcpip.ErrAborted{}
		}
		written++
		e.pktsOut.Add(1)
	}
	return written, nil
}

// writeRaw sends one fully formed IP packet to the device, applying the same
// offset contract and the same counters WritePackets uses.
//
// It exists for the packets the netstack will not send for us: an ICMP error
// whose source address is one the stack does not own would be dropped by its
// own route lookup, so it is built by hand and handed straight to the link.
func (e *endpoint) writeRaw(pkt []byte) error {
	if len(pkt) == 0 {
		return fmt.Errorf("tunfe: refusing to write an empty packet")
	}
	out := make([]byte, LinkOffset+len(pkt))
	copy(out[LinkOffset:], pkt)
	if _, err := e.link.Write([][]byte{out}, LinkOffset); err != nil {
		return fmt.Errorf("tunfe: write to the tunnel device: %w", err)
	}
	e.pktsOut.Add(1)
	return nil
}

// fail reports a device failure to the supervisor exactly once per condition,
// and logs it either way. A full channel is dropped rather than blocked on:
// nothing in the datapath may wait for a supervisor that has already gone.
func (e *endpoint) fail(err error) {
	if e.logf != nil {
		e.logf("%v", err)
	}
	select {
	case e.errs <- err:
	default:
	}
}

// endpointStats is the accounting a test asserts on.
type endpointStats struct {
	PacketsIn  uint64
	PacketsOut uint64
	ReadErrors uint64
	// ViewsOutstanding is pooled Views taken and never released. It must be
	// zero at rest; a non-zero value is the leak the plan asks to be pinned
	// with a counter.
	ViewsOutstanding uint64
}

func (e *endpoint) stats() endpointStats {
	return endpointStats{
		PacketsIn:        e.pktsIn.Load(),
		PacketsOut:       e.pktsOut.Load(),
		ReadErrors:       e.readErrs.Load(),
		ViewsOutstanding: e.viewsTaken.Load() - e.viewsFreed.Load(),
	}
}

// netProto reads the IP version nibble.
func netProto(pkt []byte) (tcpip.NetworkProtocolNumber, bool) {
	switch pkt[0] >> 4 {
	case 4:
		return header.IPv4ProtocolNumber, true
	case 6:
		return header.IPv6ProtocolNumber, true
	}
	return 0, false
}
