// Package tunfe is the privileged front end: a utun device, a gVisor netstack,
// and the same internal/flow engine proxy mode uses.
//
// TUN mode adds COVERAGE, never techniques. The upstream socket is dialled by
// the same flow.Dialer and wrapped in the same emit.SockTransport, so the
// emitter set, the ladder and the verdict cache are shared with proxy mode and
// the two front ends cannot disagree about a host.
//
// The datapath is the four steps of internal/flow/e2e_test.go's serve helper,
// with one ordering rule that is specific to a transparent front end: a flow
// that is not judged is piped IMMEDIATELY, with no first-message read at all.
// The previous implementation's unconditional, un-deadlined client.Read
// deadlocked every server-speaks-first protocol (SMTP, IMAP, POP3, FTP,
// MySQL); see tcp.go.
//
// Everything above the device is written against Link, and NewPipe supplies an
// in-memory Link pair, so the whole stack — endpoint, forwarders, relay, UDP,
// in-process DNS — runs under `go test` with no root, no utun and no network.
// That is deliberate: in the previous tree every confirmed defect lived in this
// region and every function in it was at 0.0% coverage.
//
// What this package does NOT do: choose a utun, collect the facts a bring-up
// needs, or own a netstate.Manager. Capture (stack.go) is the ordered sequence
// of system mutations TUN mode requires and it takes the Manager it is handed,
// so the command layer keeps one journal and one teardown stack for the whole
// run rather than this package growing a second one.
package tunfe

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sync"
	"sync/atomic"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/mumudevx/dpb/internal/flow"
)

// Event is a link-state change reported by the device. It mirrors
// wireguard/tun's Event set; pumpEvents below translates.
type Event uint8

const (
	EventUp Event = 1 + iota
	EventDown
	EventMTUUpdate
)

var eventNames = [...]string{"", "up", "down", "mtu-update"}

func (e Event) String() string {
	if int(e) < len(eventNames) && eventNames[e] != "" {
		return eventNames[e]
	}
	return fmt.Sprintf("event(%d)", uint8(e))
}

// Link is exactly the part of wireguard/tun.Device this package uses, narrowed
// to an interface so that everything above it is testable without root.
//
// The offset contract is wireguard/tun's own, and it is the reason this
// interface is shaped this way rather than as an io.ReadWriter: on Darwin the
// device carries a 4-byte address-family prefix before each IP packet, so Read
// fills bufs[i] from offset onwards and reports the IP packet's length in
// sizes[i], and Write reads the IP packet from bufs[i][offset:] and needs the
// four bytes BEFORE offset to be writable scratch. Passing an offset below 4
// is a programming error and every implementation reports it rather than
// silently corrupting the first four bytes of the packet.
type Link interface {
	// Read fills bufs[i][offset:] with one IP packet each and sets sizes[i] to
	// its length. It returns the number of packets read.
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	// Write sends the IP packets at bufs[i][offset:]. It returns the number of
	// packets written.
	Write(bufs [][]byte, offset int) (int, error)
	// MTU is the device MTU.
	MTU() (int, error)
	// Name is the interface name, e.g. "utun4". It is what the route and
	// ifconfig Ops are told to configure, so it must come from the device
	// rather than from the name that was requested.
	Name() (string, error)
	// Events reports link-state changes. It MUST be drained: the real device
	// feeds it from a route-socket reader goroutine over a channel of capacity
	// 10, which wedges permanently once nobody is listening.
	Events() <-chan Event
	// BatchSize is the preferred number of packets per Read/Write call.
	BatchSize() int
	// Close releases the device.
	Close() error
}

// LinkOffset is the number of bytes every Read and Write must leave in front of
// the IP packet for the Darwin address-family prefix.
const LinkOffset = 4

// ErrLinkClosed is returned by a closed Link's Read, Write and Name.
var ErrLinkClosed = errors.New("tunfe: link is closed")

// deviceLink is written against the wgDevice interface rather than
// *wgtun.NativeTun so that the translation itself — the part that could be
// wrong — is testable with a fake device and no root at all. What is left
// untested without root is exactly one syscall wrapper: OpenDevice's call to
// CreateTUN, in link_darwin.go and link_windows.go.

// wgDevice is the wireguard/tun contract, narrowed to what deviceLink uses.
type wgDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	MTU() (int, error)
	Name() (string, error)
	Events() <-chan wgtun.Event
	BatchSize() int
	Close() error
}

var _ wgDevice = (wgtun.Device)(nil)

// deviceLink adapts a wireguard/tun device to Link.
type deviceLink struct {
	dev    wgDevice
	events chan Event
}

var _ Link = (*deviceLink)(nil)

// newDeviceLink wraps dev and starts the event translator.
func newDeviceLink(dev wgDevice, logf func(string, ...any)) *deviceLink {
	l := &deviceLink{dev: dev, events: make(chan Event, 10)}
	flow.Safe("tunfe/link.events", logf, l.pumpEvents)
	return l
}

// pumpEvents translates the device's events onto our own channel.
//
// The device feeds its channel from a route-socket reader goroutine over a
// buffer of ten, and that reader wedges permanently once nobody is listening —
// after which no interface event is ever seen again. This loop is what makes
// "Events() must be drained" true no matter what the supervisor does with our
// channel: a full channel here drops the event rather than stalling the
// device's reader.
func (l *deviceLink) pumpEvents() {
	defer close(l.events)
	for ev := range l.dev.Events() {
		var out Event
		switch ev {
		case wgtun.EventUp:
			out = EventUp
		case wgtun.EventDown:
			out = EventDown
		case wgtun.EventMTUUpdate:
			out = EventMTUUpdate
		default:
			continue
		}
		select {
		case l.events <- out:
		default:
		}
	}
}

func (l *deviceLink) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if err := checkOffset(offset); err != nil {
		return 0, err
	}
	return l.dev.Read(bufs, sizes, offset)
}

func (l *deviceLink) Write(bufs [][]byte, offset int) (int, error) {
	if err := checkOffset(offset); err != nil {
		return 0, err
	}
	return l.dev.Write(bufs, offset)
}

func (l *deviceLink) MTU() (int, error)     { return l.dev.MTU() }
func (l *deviceLink) Name() (string, error) { return l.dev.Name() }
func (l *deviceLink) Events() <-chan Event  { return l.events }
func (l *deviceLink) BatchSize() int        { return l.dev.BatchSize() }
func (l *deviceLink) Close() error          { return l.dev.Close() }

// PipeLink is an in-memory Link: two of them are connected back to back, so a
// netstack on each end exchanges real IP packets with no device, no root and no
// kernel involvement at all.
//
// It is not a test double for the parts of the datapath under test — the
// endpoint, the forwarders, the relay and the DNS server are the shipped code —
// it is a test double for the SIX HUNDRED lines of kernel and driver between
// two of them.
type PipeLink struct {
	name  string
	mtu   int
	batch int

	// rx carries packets this end will Read; tx is the peer's rx.
	rx     chan []byte
	tx     chan []byte
	events chan Event

	closeOnce sync.Once
	closed    chan struct{}

	mu       sync.Mutex
	failOnce sync.Once
	failed   chan struct{}
	readErr  error

	reads   atomic.Uint64
	writes  atomic.Uint64
	dropped atomic.Uint64
}

var _ Link = (*PipeLink)(nil)

// pipeDepth is how many packets may sit in one direction before the writer
// starts dropping. A real link drops when its queue is full; blocking instead
// would let a stalled reader deadlock the netstack that feeds it.
const pipeDepth = 256

// NewPipe returns two connected PipeLinks. What a writes, b reads.
//
// mtu <= 0 means 1500, which is the utun MTU this tool configures.
func NewPipe(mtu int) (a, b *PipeLink) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	ab := make(chan []byte, pipeDepth)
	ba := make(chan []byte, pipeDepth)
	a = &PipeLink{
		name: "pipe0", mtu: mtu, batch: 1,
		rx: ba, tx: ab,
		events: make(chan Event, 10),
		closed: make(chan struct{}),
		failed: make(chan struct{}),
	}
	b = &PipeLink{
		name: "pipe1", mtu: mtu, batch: 1,
		rx: ab, tx: ba,
		events: make(chan Event, 10),
		closed: make(chan struct{}),
		failed: make(chan struct{}),
	}
	return a, b
}

// Read blocks until a packet arrives, the link is closed, or an injected
// failure is armed.
func (p *PipeLink) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if err := checkOffset(offset); err != nil {
		return 0, err
	}
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, fmt.Errorf("tunfe: pipe read: %d buffer(s) and %d size slot(s)", len(bufs), len(sizes))
	}
	if err := p.failure(); err != nil {
		return 0, err
	}
	// A closed link is checked BEFORE the queue, deterministically: a plain
	// select over both would pick at random between "closed" and "a packet is
	// waiting", so a device that had gone away would sometimes still read.
	if p.isClosed() {
		return 0, ErrLinkClosed
	}
	select {
	case <-p.closed:
		return 0, ErrLinkClosed
	case <-p.failed:
		return 0, p.failure()
	case pkt, ok := <-p.rx:
		if !ok {
			return 0, ErrLinkClosed
		}
		if len(bufs[0]) < offset+len(pkt) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		p.reads.Add(1)
		return 1, nil
	}
}

// Write hands each packet to the peer. A full queue drops rather than blocks,
// and the drop is counted so a test can tell a dropped packet from a lost one.
func (p *PipeLink) Write(bufs [][]byte, offset int) (int, error) {
	if err := checkOffset(offset); err != nil {
		return 0, err
	}
	for i, b := range bufs {
		if len(b) < offset {
			return i, io.ErrShortBuffer
		}
		if p.isClosed() {
			return i, ErrLinkClosed
		}
		pkt := make([]byte, len(b)-offset)
		copy(pkt, b[offset:])
		select {
		case p.tx <- pkt:
			p.writes.Add(1)
		default:
			p.dropped.Add(1)
		}
	}
	return len(bufs), nil
}

// isClosed reports whether Close has been called on this end.
func (p *PipeLink) isClosed() bool {
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

func (p *PipeLink) MTU() (int, error) { return p.mtu, nil }

func (p *PipeLink) Name() (string, error) {
	if p.isClosed() {
		return "", ErrLinkClosed
	}
	return p.name, nil
}

func (p *PipeLink) Events() <-chan Event { return p.events }

func (p *PipeLink) BatchSize() int { return p.batch }

func (p *PipeLink) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

// FailRead arms Read to return err instead of a packet. It is how a test drives
// the one failure the previous implementation swallowed: a device read error
// that returned silently and left the capture routes pointing at a dead device,
// which is a total IPv4 blackout with no symptom in any log.
func (p *PipeLink) FailRead(err error) {
	p.mu.Lock()
	p.readErr = err
	p.mu.Unlock()
	// Wake a reader that is already parked, so the failure is delivered without
	// the test having to inject a packet it does not want delivered.
	p.failOnce.Do(func() { close(p.failed) })
}

func (p *PipeLink) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.readErr
}

// Emit publishes a link-state event, as the real device's route-socket reader
// does.
func (p *PipeLink) Emit(e Event) {
	select {
	case p.events <- e:
	default:
	}
}

// SetName overrides the name Name() reports, so a test can assert that the
// bring-up sequence configures the device the kernel actually gave us rather
// than the one that was requested.
func (p *PipeLink) SetName(name string) { p.name = name }

// PipeStats reports what crossed one end of the pipe.
type PipeStats struct {
	Reads   uint64
	Writes  uint64
	Dropped uint64
}

// Stats reports the packet counters.
func (p *PipeLink) Stats() PipeStats {
	return PipeStats{
		Reads:   p.reads.Load(),
		Writes:  p.writes.Load(),
		Dropped: p.dropped.Load(),
	}
}

// checkOffset enforces the Darwin prefix contract. wireguard/tun returns
// io.ErrShortBuffer for a Write below offset 4 and silently corrupts a Read, so
// this is where an offset mistake becomes a visible error on both paths.
func checkOffset(offset int) error {
	if offset < LinkOffset {
		return fmt.Errorf("%w: offset %d leaves no room for the %d-byte address-family prefix",
			io.ErrShortBuffer, offset, LinkOffset)
	}
	return nil
}

// isClosedLinkErr reports whether err means "the device went away", which is a
// normal shutdown rather than a failure worth reporting to the supervisor.
func isClosedLinkErr(err error) bool {
	return errors.Is(err, ErrLinkClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) ||
		errors.Is(err, fs.ErrClosed)
}
