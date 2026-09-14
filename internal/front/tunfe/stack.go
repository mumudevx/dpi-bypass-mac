package tunfe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/resolve"
	"github.com/mumudevx/dpb/internal/strategy"
)

// nicID is the only NIC in this stack.
const nicID = tcpip.NICID(1)

// Defaults for the bounds a caller did not set. Every one is a bound, not a
// target.
const (
	// DefaultRelayIdle closes a TCP relay whose two directions have both been
	// quiet this long. It matches proxyfe.DefaultRelayIdle: the two front ends
	// must not disagree about when a connection is dead.
	DefaultRelayIdle = 120 * time.Second
	// DefaultUDPIdle reaps a UDP session after this long with no datagram in
	// either direction. UDP has no FIN, so without a reaper every flow leaks a
	// socket and two goroutines for the life of the process.
	DefaultUDPIdle = 60 * time.Second
	// DefaultDialTimeout bounds one upstream dial on the unjudged path. The
	// ladder owns its own budget on the judged path.
	DefaultDialTimeout = 10 * time.Second
	// DefaultDrainGrace bounds the wait for live connections at shutdown.
	// Teardown has a 10 s budget in total and the system routes still have to
	// be reverted inside it.
	DefaultDrainGrace = 3 * time.Second
	// tcpRecvBuf is the per-connection receive window the forwarder advertises.
	// Zero would leave gVisor's default; this is one 64 KiB window, which is
	// what a 1500-byte MTU link fills comfortably.
	tcpRecvBuf = 1 << 16
	// tcpMaxInFlight bounds half-open forwarded connections.
	tcpMaxInFlight = 2048
)

var (
	// ErrNoLink is returned by New when no device was supplied.
	ErrNoLink = errors.New("tunfe: no link device")
	// ErrNoLadder is returned by New when the engine is missing. Failing at
	// construction is the only way it never becomes a datapath that silently
	// relays every captured flow unjudged.
	ErrNoLadder = errors.New("tunfe: no ladder runner")
	// ErrNoScope is returned by New when no policy scope was supplied.
	ErrNoScope = errors.New("tunfe: no policy scope")
	// ErrNoUDPDialer is reported when a UDP flow needs to be relayed and no
	// UDP dialer was wired.
	ErrNoUDPDialer = errors.New("tunfe: no UDP dialer")
	// ErrNoQUICStrategy is returned by New when QUICDesync was selected with no
	// strategy to emit. Refusing at construction is the point: the alternative
	// is a policy that claims to desync QUIC and relays it plain.
	ErrNoQUICStrategy = errors.New("tunfe: quic = desync needs a UDP strategy")
)

// UDPDialer opens the upstream socket for a relayed datagram flow.
//
// It is a separate interface from flow.Dialer because flow deals in streams,
// and because the datagram path must never reach net.Dial with anything but an
// address: the destination here is already a netip.AddrPort taken off the
// packet, so no name is ever resolved on this path (MEASUREMENTS.md §5.4).
type UDPDialer interface {
	DialUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

// Options configures a Server. Everything is injected — the scope, the engine,
// the dialers, the resolver, the clock — because this package has no global
// state and opens no socket and no device it was not handed.
type Options struct {
	// Link is the tunnel device. The Server never closes it: the teardown
	// ordering closes the utun LAST, after the routes naming it are gone, and
	// only the caller knows when that has happened.
	Link Link
	// MTU is the netstack MTU. Zero reads it from the device.
	MTU int
	// Scope decides what happens to a flow before any byte is read.
	Scope policy.Scope
	// Ladder is the shared engine. It owns dialling for a judged flow.
	Ladder *flow.LadderRunner
	// Dial opens the upstream for a flow that is NOT judged. Nil falls back to
	// the ladder's own dialer.
	Dial flow.Dialer
	// UDPDial opens the upstream for a relayed datagram flow.
	UDPDial UDPDialer
	// Reverse names a flow from the DNS answers we ourselves served. It is what
	// replaces a fake-IP layer: a user who excluded their bank keeps that
	// exclusion in TUN mode, where the flow arrives as a bare address.
	Reverse policy.ReverseMap
	// DNS answers UDP/53 and TCP/53 in process. Relaying them would hand the
	// ISP's resolver exactly the queries DoH exists to hide.
	DNS *resolve.Server
	// QUIC selects what happens to a UDP/443 QUIC Initial addressed to a name
	// we judge. The zero value is QUICRefuse, which is the shipped default.
	QUIC QUICPolicy
	// QUICStrategy is the plan QUICDesync emits an Initial through. It is
	// required by that policy and ignored by every other one, and New refuses a
	// strategy a connected UDP socket cannot satisfy rather than discovering
	// the shortfall per datagram on an open socket.
	QUICStrategy strategy.Strategy
	// Sender executes a UDP plan. Nil is the shared default sender; a caller
	// that owns the process-wide small-write governor should pass its own.
	Sender *emit.Sender
	// FirstMsg bounds the first-message read. The zero value is
	// flow.DefaultFirstMsgOpts().
	FirstMsg flow.FirstMsgOpts
	// RelayIdle, UDPIdle and DialTimeout are bounds; zero means the defaults.
	RelayIdle   time.Duration
	UDPIdle     time.Duration
	DialTimeout time.Duration
	// DrainGrace bounds the wait for live flows at shutdown.
	DrainGrace time.Duration
	// OnConn receives one event per finished TCP flow. May be nil.
	OnConn func(observ.ConnEvent)
	Now    func() time.Time
	Logf   func(string, ...any)
}

// Stats is what `dpb status` reads off a running tunnel.
type Stats struct {
	TCPFlows  uint64
	UDPFlows  uint64
	DNSFlows  uint64
	Refused   uint64
	Failed    uint64
	Escalated uint64
	Active    int64

	PacketsIn        uint64
	PacketsOut       uint64
	ReadErrors       uint64
	ViewsOutstanding uint64
}

// Server runs a gVisor netstack over a tunnel device and relays what it
// captures through the same engine proxy mode uses.
type Server struct {
	o  Options
	st *stack.Stack
	ep *endpoint

	// ctx is the lifetime of the datapath. Every flow derives from it, so
	// shutdown ends the relays instead of leaving them to discover a dead
	// netstack, and drain can actually drain rather than time out.
	ctx    context.Context
	cancel context.CancelFunc

	// wg counts the live flows and drained closes the counter.
	//
	// They are one unit guarded by one mutex because sync.WaitGroup's contract
	// forbids an Add that races a Wait, and the two sides of that race are
	// exactly what this datapath does at shutdown: drain() calls Wait while the
	// device read loop is still delivering packets to the forwarders, each of
	// which calls track. The race detector catches it directly (see
	// TestTrackAndDrainDoNotRaceOnTheFlowCounter); the sync contract says the
	// outcome is undefined, and the observable failures are a flow the drain
	// never waits for and a WaitGroup misuse panic.
	trackMu sync.Mutex
	wg      sync.WaitGroup
	drained bool

	tcpFlows  atomic.Uint64
	udpFlows  atomic.Uint64
	dnsFlows  atomic.Uint64
	refused   atomic.Uint64
	failed    atomic.Uint64
	escalated atomic.Uint64
	active    atomic.Int64
	nextID    atomic.Uint64

	closeOnce sync.Once
}

// New builds the netstack and registers the forwarders. It does not start the
// datapath: CreateNIC attaches the endpoint, and Serve supervises it.
func New(o Options) (*Server, error) {
	if o.Link == nil {
		return nil, ErrNoLink
	}
	if o.Ladder == nil {
		return nil, ErrNoLadder
	}
	if o.Scope == nil {
		return nil, ErrNoScope
	}
	if o.Dial == nil {
		o.Dial = o.Ladder.Dial
	}
	if o.Dial == nil {
		return nil, fmt.Errorf("tunfe: no dialer")
	}
	if o.MTU <= 0 {
		mtu, err := o.Link.MTU()
		if err != nil {
			return nil, fmt.Errorf("tunfe: read device MTU: %w", err)
		}
		o.MTU = mtu
	}
	if o.MTU <= 0 {
		o.MTU = DefaultMTU
	}
	if o.FirstMsg == (flow.FirstMsgOpts{}) {
		o.FirstMsg = flow.DefaultFirstMsgOpts()
	}
	if o.RelayIdle <= 0 {
		o.RelayIdle = DefaultRelayIdle
	}
	if o.UDPIdle <= 0 {
		o.UDPIdle = DefaultUDPIdle
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.DrainGrace <= 0 {
		o.DrainGrace = DefaultDrainGrace
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := checkQUIC(o); err != nil {
		return nil, err
	}

	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{o: o, st: st, ctx: ctx, cancel: cancel}

	// Register the forwarders BEFORE the NIC exists. CreateNIC attaches the
	// endpoint, which starts the read loop immediately; a packet arriving in
	// the window between those two calls would find no handler and be answered
	// with a reset the client would remember.
	tcpFwd := tcp.NewForwarder(st, tcpRecvBuf, tcpMaxInFlight, s.handleTCP)
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(st, s.handleUDP)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	s.ep = newEndpoint(o.Link, uint32(o.MTU), o.Logf)
	if err := st.CreateNIC(nicID, s.ep); err != nil {
		cancel()
		st.Close()
		return nil, fmt.Errorf("tunfe: create NIC: %v", err)
	}
	// Promiscuous mode accepts packets addressed to anyone, and spoofing lets
	// us answer as the destination the client believes it is talking to. Both
	// are what makes a transparent front end possible at all: the netstack owns
	// no address the client has ever heard of.
	if err := st.SetPromiscuousMode(nicID, true); err != nil {
		cancel()
		st.Close()
		return nil, fmt.Errorf("tunfe: set promiscuous mode: %v", err)
	}
	if err := st.SetSpoofing(nicID, true); err != nil {
		cancel()
		st.Close()
		return nil, fmt.Errorf("tunfe: set spoofing: %v", err)
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	return s, nil
}

// checkQUIC is the capability validator for the datagram path, run at
// construction.
//
// The plan's rule is that a profile naming a strategy the selected transport
// cannot satisfy must REFUSE TO LOAD with the shortfall named, rather than
// degrade silently. The datagram path has no ladder to fall back to, so the
// alternative here is worse than usual: every Initial would be refused at
// emission time and the operator would see a tunnel that quietly kills QUIC
// while claiming to desync it.
//
// Both address families are checked, because the destination is not known until
// a packet arrives and a strategy that works only over IPv4 is not a strategy
// this server can promise.
func checkQUIC(o Options) error {
	if o.QUIC != QUICDesync {
		return nil
	}
	if o.QUICStrategy.IsPlain() {
		return ErrNoQUICStrategy
	}
	have := emit.UDPCaps(false) & emit.UDPCaps(true)
	if miss := have.Missing(o.QUICStrategy.Caps()); miss != 0 {
		return fmt.Errorf("tunfe: %s needs %s and a connected UDP socket on this machine offers %s (missing %s)",
			o.QUICStrategy.Label(), o.QUICStrategy.Caps(), have, miss)
	}
	return nil
}

// Serve supervises the datapath until ctx is cancelled or the device fails.
//
// It returns nil for a cancelled context — that is a normal shutdown — and the
// device's error otherwise. A device error is NOT recoverable here: the capture
// routes still point at this device, so the supervisor must tear the whole
// datapath down rather than keep running over a link that reads nothing.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	events := s.o.Link.Events()
	// Ending the supervisor ends the flows: whether this returns because the
	// run is shutting down or because the device failed, a relay over a
	// datapath that is finished has nothing left to carry.
	defer s.drain()
	defer s.cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-s.ep.Errors():
			return err
		case ev, ok := <-events:
			if !ok {
				// The device closed its event channel. Keep serving: the read
				// loop reports the device going away, and it is the authority.
				events = nil
				continue
			}
			// The channel MUST be drained. The real device feeds it from a
			// route-socket reader over a channel of capacity 10, and that
			// reader wedges permanently once nobody is listening — after which
			// no interface event is ever seen again.
			s.logf("tunfe: device event: %s", ev)
		}
	}
}

// Close tears the netstack down. It does NOT close the device: the teardown
// ordering closes the utun last, after every route naming it is gone, because
// `route delete` naming a closed interface fails.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.st.Close()
	})
}

// Errors reports a device failure to a caller that supervises the datapath some
// other way than by calling Serve.
func (s *Server) Errors() <-chan error { return s.ep.Errors() }

// Stats reports the counters.
func (s *Server) Stats() Stats {
	es := s.ep.stats()
	return Stats{
		TCPFlows:         s.tcpFlows.Load(),
		UDPFlows:         s.udpFlows.Load(),
		DNSFlows:         s.dnsFlows.Load(),
		Refused:          s.refused.Load(),
		Failed:           s.failed.Load(),
		Escalated:        s.escalated.Load(),
		Active:           s.active.Load(),
		PacketsIn:        es.PacketsIn,
		PacketsOut:       es.PacketsOut,
		ReadErrors:       es.ReadErrors,
		ViewsOutstanding: es.ViewsOutstanding,
	}
}

// drain waits for live flows, but only for DrainGrace. A relay wedged on a
// socket that will never return must not hold up the revert of the capture
// routes: the process is about to exit and take the socket with it, whereas an
// unreverted route outlives us.
func (s *Server) drain() {
	// The counter is CLOSED before it is waited on, and that order is the whole
	// point: from here on track admits nothing, so the Wait below cannot race
	// an Add. A flow that arrives after this line is refused by its forwarder
	// rather than started on a netstack that is being torn down.
	s.trackMu.Lock()
	s.drained = true
	s.trackMu.Unlock()

	done := make(chan struct{})
	flow.Safe("tunfe/drain", s.o.Logf, func() {
		defer close(done)
		s.wg.Wait()
	})
	t := time.NewTimer(s.o.DrainGrace)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		s.logf("tunfe: %d flow(s) still live after %s; leaving them to process exit",
			s.active.Load(), s.o.DrainGrace)
	}
}

// track runs one flow on a guarded goroutine, counted so shutdown can wait for
// it.
//
// It reports whether the flow was admitted. False means drain has closed the
// counter and this datapath will never run another flow; it is not an error,
// but the CALLER MUST release whatever the netstack already handed it — a
// created endpoint, or a forwarder request that still owes the client an
// answer — because nothing else will.
func (s *Server) track(name string, fn func()) bool {
	s.trackMu.Lock()
	if s.drained {
		s.trackMu.Unlock()
		return false
	}
	s.wg.Add(1)
	s.trackMu.Unlock()

	s.active.Add(1)
	flow.Safe(name, s.o.Logf, func() {
		defer s.wg.Done()
		defer s.active.Add(-1)
		fn()
	})
	return true
}

func (s *Server) logf(format string, a ...any) {
	if s.o.Logf != nil {
		s.o.Logf(format, a...)
	}
}

// ══════════════════════ system-state bring-up ══════════════════════

// Sequencer is the part of *netstate.Manager this package needs. Every system
// mutation goes through it, so every one of them is journalled, independently
// verified through a different subsystem, and revertible by a later process
// that finds the journal after a SIGKILL.
type Sequencer interface {
	Do(ctx context.Context, op netstate.Op) error
	UndoAll(ctx context.Context) []error
}

// CaptureRoutes are the two halves of the IPv4 space. They are used rather than
// a default route so that the machine's real default route survives untouched
// underneath, which is what lets our own upstream sockets escape by binding to
// the uplink instead of needing an exclusion route per destination.
func CaptureRoutes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
}

// CaptureRoutesV6 is the same pair for IPv6.
//
// Capturing v6 is not symmetry for its own sake. DOSSIER GT19 records that the
// IPv6 sinkhole 2a01:358:4014:a00::3 is registered in RIPE to BTK itself, so
// AAAA poisoning is half of the block here — and a tunnel that captures only
// IPv4 while the resolver hands applications real AAAA records gives them
// addresses for traffic it cannot protect. Either this pair is installed and
// verified, or AAAA is suppressed (IPv6Gate, resolve.Options.V6Protected).
// There is no third option that is not a silent leak.
func CaptureRoutesV6() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
}

// IPv6Gate is the fail-closed link between the tunnel's IPv6 capture and the
// resolver's AAAA policy.
//
// It is open ONLY while every IPv6 capture route has been applied AND verified
// against the kernel routing table. A zero gate, a nil gate, a bring-up that
// failed halfway and a tunnel that was torn down all read closed, which is what
// makes forgetting to wire it safe: the resolver answers AAAA with NOERROR and
// an SOA rather than with an address nothing is protecting.
//
// Pass the Captured method as resolve.Options.V6Protected.
type IPv6Gate struct{ captured atomic.Bool }

// Captured reports whether IPv6 is being carried by this tunnel right now. A
// nil gate reports false: no gate means nobody claimed IPv6 is protected.
func (g *IPv6Gate) Captured() bool { return g != nil && g.captured.Load() }

// Set records the verified state of the IPv6 capture. Bring-up opens it after
// the last v6 route verifies; teardown and any re-verification that finds a
// route missing must close it.
func (g *IPv6Gate) Set(captured bool) {
	if g != nil {
		g.captured.Store(captured)
	}
}

// Capture is the system-state half of TUN mode: the ifconfig and route Ops, in
// the order docs/PLAN.md data path F specifies, each verified through a
// different subsystem than the one that applied it before the next is
// attempted.
//
// The ordering is the contract. Bring-up must configure the interface before
// any route names it, and teardown must delete every route before the device
// closes, because macOS `route delete` naming a closed interface fails — and
// route(8) reports that failure with exit status 0, which is why every step
// here goes through netstate rather than through a Runner directly.
type Capture struct {
	// Iface is the device name the kernel gave us, read back from the device
	// rather than the name that was requested.
	Iface string
	// Local and Peer are the point-to-point addresses of the tunnel. A utun
	// needs both: without a peer the kernel has no destination to attach the
	// interface route to.
	Local netip.Addr
	Peer  netip.Addr
	MTU   int
	// LocalV6 is the tunnel's own IPv6 address. When it is unset, IPv6 is NOT
	// captured and IPv6Gate stays closed — which the resolver reads as "do not
	// hand applications AAAA records".
	LocalV6 netip.Addr
	// GatewayV6 is the machine's real IPv6 next hop. It gets the same
	// interface-scoped default route the v4 gateway does, so our own upstream
	// sockets can still reach a v6 origin once ::/1 and 8000::/1 point at the
	// tunnel. Unset means the v6 capture routes are installed without a v6
	// escape route, which is correct on a v4-only uplink and is why BringUp
	// does not require it.
	GatewayV6 netip.Addr
	// RoutesV6 are the IPv6 capture prefixes. Nil means CaptureRoutesV6().
	RoutesV6 []netip.Prefix
	// V6Gate is opened once every IPv6 capture route is verified and closed by
	// TearDown. Nil is allowed and reads as "IPv6 is not protected".
	V6Gate *IPv6Gate
	// Uplink and Gateway describe the real default route. The scoped default
	// (`route add default <gw> -ifscope <uplink>`) is what lets our own
	// upstream sockets reach the internet once the capture routes are in
	// place.
	Uplink  string
	Gateway netip.Addr
	// Routes are the capture prefixes. Nil means CaptureRoutes().
	Routes []netip.Prefix
	// Nameservers get host routes into the tunnel. A resolver on the local
	// subnet is reached by the interface's own subnet route, which is more
	// specific than 0.0.0.0/1, so without these the machine's own DNS would be
	// the one flow that escaped capture.
	Nameservers []netip.Addr
	// Resolvers and Services point the named network services at the tunnel's
	// own resolver. Empty means DNS is left alone.
	Resolvers []string
	Services  []string
	// Runner executes the commands. Nil uses the Env's runner.
	Runner netstate.Runner
	Logf   func(string, ...any)
}

// BringUp applies every system mutation in order, calling start between the
// scoped default route and the capture routes.
//
// start is where the datapath comes up. It sits there on purpose: the capture
// routes must not exist before something is listening behind them (that window
// is a blackhole), and they must not be installed before our own escape route
// exists (that window is a loop).
func (c Capture) BringUp(ctx context.Context, seq Sequencer, start func(context.Context) error) error {
	if seq == nil {
		return errors.New("tunfe: bring-up needs a sequencer")
	}
	if c.Iface == "" {
		return errors.New("tunfe: bring-up needs the device name")
	}
	if !c.Local.IsValid() {
		return errors.New("tunfe: bring-up needs a tunnel address")
	}
	mtu := c.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	// The gate is closed for the whole of bring-up. It opens after the last
	// IPv6 capture route has verified and never before: every early return
	// below leaves it shut, so a half-installed capture reads as "IPv6 is not
	// protected" and AAAA is suppressed rather than answered.
	c.V6Gate.Set(false)

	peer := ""
	if c.Peer.IsValid() {
		peer = c.Peer.String()
	}
	if err := seq.Do(ctx, netstate.NewIfconfig(c.Runner, c.Iface, c.Local.String(), peer, mtu)); err != nil {
		return fmt.Errorf("tunfe: configure %s: %w", c.Iface, err)
	}
	if c.LocalV6.IsValid() {
		// A second address on the same interface, not a second interface. It is
		// added before any v6 route names the device, exactly as for v4.
		if err := seq.Do(ctx, netstate.NewIfconfig(c.Runner, c.Iface, c.LocalV6.String(), "", mtu)); err != nil {
			return fmt.Errorf("tunfe: configure %s inet6: %w", c.Iface, err)
		}
	}

	// The scoped defaults first, and before the datapath starts: they are the
	// routes our own upstream sockets take, and installing the capture routes
	// without them is how a tunnel eats its own resolver traffic.
	//
	// # Why this loop is NOT skipped on Windows, where there is no scope flag
	//
	// The tempting argument is that longest-prefix-match already protects us:
	// CaptureRoutes are 0.0.0.0/1 and 128.0.0.0/1, the machine's default is
	// 0.0.0.0/0, so surely our own sockets keep taking the default. That is
	// BACKWARDS, on every platform. A /1 is MORE specific than a /0, so an
	// ordinary route lookup prefers the capture route and sends the packet into
	// our own tunnel. DOSSIER.md records the bug that proves it: the raw
	// injector "sets only IP_HDRINCL, never IP_BOUND_IF; unix.Sendto does an
	// unscoped route lookup; 0.0.0.0/1 -> utun is more specific than the
	// -ifscope en0 default, so the decoy is written back into dpb's own tun
	// device". Nothing about Windows changes that arithmetic.
	//
	// What actually keeps our upstream sockets out of the tunnel is the
	// INTERFACE PIN, not the prefix length: flow.NetDialer.Interface is set to
	// the uplink (cliapp/tunrun.go, tunUplink) and flow's bindToInterface pins
	// every upstream socket to it. That restricts the route lookup to routes on
	// the uplink, where the capture routes — which live on the utun — are not
	// candidates and the default is. macOS then needs a row carrying
	// RTF_IFSCOPE for that restricted lookup to resolve, which is the row this
	// loop adds and the reason the comment above says "scoped".
	//
	// Windows has no RTF_IFSCOPE, so the row this loop asks for is the row the
	// machine already has — and that is handled, deliberately, one layer down
	// rather than by a build tag here. netstate.Manager.Do runs Verify BEFORE
	// Apply and routeOp.canAdopt() is true, so on Windows this Op is ADOPTED:
	// scwindows reads Facts.Uplink and Facts.Gateway out of the very default
	// row matchRoute then finds (Scoped means "has a next hop" there), Apply is
	// never reached, CreateIpForwardEntry2 is never called, and teardown leaves
	// the machine's own default alone. See routeOp.canAdopt for the full
	// argument, and netstate's route adoption tests for the pinned behaviour.
	//
	// Keeping the Op rather than skipping it is what buys the check: adoption
	// is a POSITIVE reading of the kernel table saying the escape route is
	// really there. Skip the Op and a machine whose default vanished between
	// facts collection and bring-up gets its capture routes installed with
	// nothing to escape through — the blackhole this ordering exists to
	// prevent.
	if c.Uplink != "" {
		for _, gw := range []netip.Addr{c.Gateway, c.GatewayV6} {
			if !gw.IsValid() {
				continue
			}
			dst := netip.MustParsePrefix("0.0.0.0/0")
			if gw.Is6() {
				dst = netip.MustParsePrefix("::/0")
			}
			if err := seq.Do(ctx, netstate.NewRoute(c.Runner, dst, gw, c.Uplink)); err != nil {
				return fmt.Errorf("tunfe: scope the %s default route to %s: %w", dst, c.Uplink, err)
			}
		}
	}

	if start != nil {
		if err := start(ctx); err != nil {
			return fmt.Errorf("tunfe: start the datapath: %w", err)
		}
	}

	routes := c.Routes
	if routes == nil {
		routes = CaptureRoutes()
	}
	for _, p := range routes {
		if err := seq.Do(ctx, netstate.NewRoute(c.Runner, p, netip.Addr{}, c.Iface)); err != nil {
			return fmt.Errorf("tunfe: capture %s: %w", p, err)
		}
	}

	if c.LocalV6.IsValid() {
		v6 := c.RoutesV6
		if v6 == nil {
			v6 = CaptureRoutesV6()
		}
		if len(v6) == 0 {
			// An explicitly empty route set means the caller asked for an IPv6
			// address on the device and no capture. The gate stays shut: an
			// address is not a capture, and opening on one would serve AAAA for
			// traffic that leaves by the machine's own default route.
			return fmt.Errorf("tunfe: %s has an IPv6 address but no capture routes; "+
				"either capture ::/1 and 8000::/1 or leave LocalV6 unset", c.Iface)
		}
		for _, p := range v6 {
			// seq.Do returns only after the route was read back out of the
			// kernel routing table, so reaching the end of this loop IS the
			// verification the gate is allowed to open on.
			if err := seq.Do(ctx, netstate.NewRoute(c.Runner, p, netip.Addr{}, c.Iface)); err != nil {
				return fmt.Errorf("tunfe: capture %s: %w", p, err)
			}
		}
		c.V6Gate.Set(true)
	}

	for _, ns := range c.Nameservers {
		p, err := hostPrefix(ns)
		if err != nil {
			return fmt.Errorf("tunfe: capture nameserver %s: %w", ns, err)
		}
		if err := seq.Do(ctx, netstate.NewRoute(c.Runner, p, netip.Addr{}, c.Iface)); err != nil {
			return fmt.Errorf("tunfe: capture nameserver %s: %w", ns, err)
		}
	}

	if len(c.Resolvers) > 0 && len(c.Services) > 0 {
		if err := seq.Do(ctx, netstate.NewDNSServers(c.Runner, c.Resolvers, c.Services)); err != nil {
			return fmt.Errorf("tunfe: point DNS at the tunnel: %w", err)
		}
	}
	return nil
}

// TearDown reverts every applied Op and only then stops the datapath and closes
// the device.
//
// ctx must be a FRESH context, never the cancelled one that ended the run:
// every Op's journal write checks ctx.Err() first, so a cancelled context
// reverts nothing and leaves the machine captured by a process that has exited.
//
// This is one step short of the exact reverse of BringUp, and deliberately so.
// The plan's reverse order would stop the datapath while the capture routes
// still point at it, blackholing every live flow for the length of the route
// deletions; deleting the routes first means the machine is routing normally
// again before anything is torn down. The device is still closed LAST, which is
// the ordering that actually matters: `route delete` naming a closed interface
// fails, and macOS route(8) reports that failure with exit status 0.
func (c Capture) TearDown(ctx context.Context, seq Sequencer, stop func(), link Link) []error {
	// Closed FIRST, before a single route is deleted: from here on nothing this
	// process answers may hand an application an IPv6 address, because from
	// here on nothing is carrying IPv6.
	c.V6Gate.Set(false)

	var errs []error
	if seq != nil {
		errs = append(errs, seq.UndoAll(ctx)...)
	}
	if stop != nil {
		stop()
	}
	if link != nil {
		if err := link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tunfe: close %s: %w", c.Iface, err))
		}
	}
	return errs
}

// hostPrefix turns an address into its single-address prefix: /32 for IPv4 and
// /128 for IPv6.
func hostPrefix(a netip.Addr) (netip.Prefix, error) {
	if !a.IsValid() {
		return netip.Prefix{}, fmt.Errorf("tunfe: %v is not an address", a)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
