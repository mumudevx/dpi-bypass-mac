// Package netwatch is the laptop-reality layer.
//
// A MacBook is not a server. It sleeps with the lid closed, walks from a home
// Wi-Fi to a phone hotspot to a hotel network behind a captive portal, and has
// a corporate VPN switched on underneath a running process. Every one of those
// invalidates something this tool believes: the verdict cache is namespaced by
// the network it was learned on, the routes and proxy settings were applied to
// an interface that may no longer exist, and the resolver chain's answers came
// from a resolver that is no longer reachable.
//
// # What "fail closed" means here, and why
//
// For a censorship tool the phrase points two ways at once. Failing closed
// protects the user from leaking a plaintext SNI; failing closed also means
// cutting the network of somebody who is mid-transfer on a hotel Wi-Fi, and a
// tool that does that gets uninstalled, after which it protects nobody. This
// package resolves the tension by splitting the two halves apart:
//
//   - The verdict namespace fails CLOSED. While the watcher is unsure which
//     network it is on, no learned verdict from another network is applied and
//     nothing is written. MEASUREMENTS.md §5.1 is the reason: 10 of 41 hosts —
//     every Turkish bank and .gov.tr site tested — regress under the winning
//     emitter, so replaying "discord.com needs tlsfrag" onto a network where
//     plain works costs breakage, while withholding a verdict costs one ladder
//     walk of latency. The asymmetry is not close.
//   - The datapath fails OPEN. Traffic keeps flowing while the watcher settles,
//     relayed with nothing buffered and no desync applied. This leaks nothing
//     that would not have leaked anyway: the shipped policy is default-direct,
//     so attempt one for an unknown host is a plain ClientHello whether dpb is
//     confident or not (docs/PLAN.md, "Risks": "Default-direct leaks one plain
//     ClientHello per host per network before escalating").
//   - A captive portal SUSPENDS rather than fights. Everything goes ScopeDirect
//     and the PAC renders all-DIRECT, so the portal's own login page loads. The
//     alternative — desyncing handshakes against a middlebox that is meant to
//     intercept them — makes the network unusable and the portal unreachable.
//   - There is exactly one place that stops the process: a full-tunnel VPN
//     underneath a run that needs to capture traffic. There the honest answer
//     is that our capture routes cannot be made to work, and reporting "Ready"
//     while capturing nothing is the failure mode docs/PLAN.md's verification
//     contract exists to prevent. That exits 5, refused-for-safety.
//
// Nothing in this package is load-bearing for correctness on its own. The
// sleep detector is advisory (the routing-socket churn on wake is the primary
// signal), a failed portal probe is never a portal verdict, and a failed facts
// collection leaves the previous belief in place rather than inventing a new
// one. A watcher that is wrong is a watcher that revalidates too often.
package netwatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/policy"
)

// Kind names what happened.
type Kind uint8

const (
	// KindRouteChange is a debounced burst of routing-table churn that did not
	// change the network's identity. It still costs a re-verify: macOS flushes
	// interface routes on a link change, so state we applied can vanish
	// underneath us without the network being a different one.
	KindRouteChange Kind = iota + 1
	// KindNetworkChange is a new NetworkID. It swaps the verdict namespace.
	KindNetworkChange
	// KindUplinkLost is "there is no default route at all".
	KindUplinkLost
	// KindUplinkBack is the recovery from KindUplinkLost.
	KindUplinkBack
	// KindWake is the wall-vs-monotonic divergence that says the machine slept.
	KindWake
	KindPortalDetected
	KindPortalCleared
	// KindVPNFullTunnel is a VPN owning the whole address space. It is fatal
	// only when this run needs to capture traffic; in proxy mode it is
	// reported and lived with.
	KindVPNFullTunnel
	// KindError is a step that failed. It never changes what is believed; it
	// is emitted so a user running with -v can see the watcher struggling.
	KindError
)

func (k Kind) String() string {
	switch k {
	case KindRouteChange:
		return "route-change"
	case KindNetworkChange:
		return "network-change"
	case KindUplinkLost:
		return "uplink-lost"
	case KindUplinkBack:
		return "uplink-back"
	case KindWake:
		return "wake"
	case KindPortalDetected:
		return "portal-detected"
	case KindPortalCleared:
		return "portal-cleared"
	case KindVPNFullTunnel:
		return "vpn-full-tunnel"
	case KindError:
		return "error"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Suspend reasons. They are identifiers rather than sentences because the
// caller holds one suspension per reason and must be able to release exactly
// the one it took; ReasonText renders the sentence a user reads.
const (
	ReasonSettling = "network-change"
	ReasonUplink   = "uplink-lost"
	ReasonPortal   = "captive-portal"
)

// ReasonText is what `dpb status` prints for a suspension.
func ReasonText(reason string) string {
	switch reason {
	case ReasonSettling:
		return "the network changed and is being re-verified"
	case ReasonUplink:
		return "there is no uplink"
	case ReasonPortal:
		return "a captive portal is intercepting this network"
	}
	return reason
}

// Event is one thing the watcher observed. It is a value, and the fields that
// do not apply to a Kind are zero.
type Event struct {
	Kind Kind
	At   time.Time
	// NetID and Prev are set on KindNetworkChange.
	NetID policy.NetworkID
	Prev  policy.NetworkID
	// Uplink is the interface carrying the default route, when there is one.
	Uplink string
	// Iface names the VPN interface on KindVPNFullTunnel.
	Iface string
	// Gap is the detected sleep duration on KindWake.
	Gap time.Duration
	// Portal carries the portal verdict on KindPortalDetected.
	Portal Portal
	// Detail is a human sentence. Err is set on KindError.
	Detail string
	Err    error
}

func (e Event) String() string {
	s := e.Kind.String()
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Handler is what the running process does about a change.
//
// It is a struct of funcs rather than an interface for the same reason
// observ.Handler is: every hook is optional, a nil one is a no-op, and a
// caller that only wants the events does not have to write five empty methods.
// Every hook is called from the watcher's single goroutine, in the order
// below, and may block — the watcher's step budget bounds it.
type Handler struct {
	// Suspend and Unsuspend take and release one named hold. The watcher
	// guarantees they are balanced: it never releases a hold it did not take,
	// and it never takes the same hold twice. The caller must treat holds as a
	// set, so that `dpb off` and a captive portal can both be in force and
	// releasing one does not lift the other.
	Suspend   func(ctx context.Context, reason string, ev Event)
	Unsuspend func(ctx context.Context, reason string, ev Event)

	// Quiesce drops the state that belonged to the old network: the DNS answer
	// cache, idle upstream sockets, RTT estimates. It runs after the datapath
	// is already suspended, so nothing is being decided while it runs.
	Quiesce func(ctx context.Context, ev Event)

	// Namespace installs the new verdict namespace. It runs before Reverify
	// and before the datapath is resumed, so no connection is ever judged
	// against the previous network's cache.
	Namespace func(ctx context.Context, id policy.NetworkID)

	// Reverify re-checks every applied system mutation against the subsystem
	// that can see it and re-applies what went missing.
	Reverify func(ctx context.Context) error

	// Resume is the last step of a settle. Reverify has run and the namespace
	// is current.
	Resume func(ctx context.Context, ev Event)

	// Stop is the refuse-for-safety exit: a full-tunnel VPN under a run that
	// must capture traffic. The watcher calls it once and then returns.
	Stop func(ctx context.Context, ev Event, err error)

	// Observe sees every event, including the ones no other hook reacts to.
	Observe func(ev Event)
}

// Source delivers a signal every time the kernel's routing table changes.
// route_darwin.go has the PF_ROUTE implementation; a test uses a channel.
type Source interface {
	// Run blocks until ctx is done or the source fails, sending one value on
	// out per routing message. It must not close out, and it must return
	// promptly once ctx is done.
	Run(ctx context.Context, out chan<- struct{}) error
}

// Facter re-collects the machine's network identity. It is
// netstate.CollectFacts bound to an Env.
type Facter func(ctx context.Context) (*netstate.Facts, error)

// IDer turns facts into the verdict namespace. It is cliapp's networkID.
type IDer func(*netstate.Facts) policy.NetworkID

// Instant is one reading of both clocks, taken together.
type Instant struct {
	// Mono carries a monotonic reading. On darwin it comes from
	// mach_absolute_time, which does not advance while the machine is asleep.
	Mono time.Time
	// Wall is the same instant with the monotonic reading stripped, so
	// subtracting two Walls measures wall-clock time, sleep included.
	Wall time.Time
}

// Clock is netwatch's view of time. Two readings, taken together, because
// their divergence is the sleep signal.
type Clock interface {
	Now() Instant
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() Instant {
	t := time.Now()
	// Round(0) strips the monotonic reading, which is what makes the second
	// field a wall clock. Both come from ONE time.Now call so the two axes
	// cannot be skewed by the scheduler between them.
	return Instant{Mono: t, Wall: t.Round(0)}
}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RealClock is the shipped clock.
func RealClock() Clock { return realClock{} }

// Defaults. Each is docs/PLAN.md's number where the plan gives one.
const (
	// DefaultDebounce is the plan's 750 ms: one network change produces a
	// burst of routing messages and re-collecting facts per message would
	// spawn a dozen scutil invocations for one event.
	DefaultDebounce = 750 * time.Millisecond
	// DefaultMaxDebounce caps how long a continuous stream of churn can
	// postpone the reaction. Without it, a flapping link starves the settle
	// that the flapping is evidence we need.
	DefaultMaxDebounce = 5 * time.Second
	// DefaultSleepTick and DefaultSleepGap are the plan's 5 s ticker and 10 s
	// divergence threshold.
	DefaultSleepTick = 5 * time.Second
	DefaultSleepGap  = 10 * time.Second
	// DefaultPortalPoll is how often a suspended-for-portal watcher re-probes.
	// A user logging in to a hotel portal should not wait a minute for dpb to
	// notice; probing every few seconds would make dpb the noisiest client on
	// the network.
	DefaultPortalPoll = 15 * time.Second
	// DefaultStepBudget bounds one hook or one facts collection. scutil and
	// networksetup can hang on a network that is halfway up.
	DefaultStepBudget = 10 * time.Second
	// DefaultSourceRetry is how long the watcher waits before re-opening a
	// routing socket that failed. Losing the socket costs the primary signal
	// but not correctness — the sleep ticker still revalidates.
	DefaultSourceRetry = 30 * time.Second
)

// Options configures a Watcher. Every duration takes its default from zero.
type Options struct {
	// Source is the routing-socket reader. Nil means NewRouteSource().
	Source Source
	// Facts and NetID are required: without them there is no way to tell one
	// network from another, which is the whole job.
	Facts Facter
	NetID IDer
	// Initial is the namespace the process is already using. The first
	// comparison is made against it, so a start-up followed immediately by a
	// route flap does not look like a network change.
	Initial policy.NetworkID
	// Portal is the captive-portal prober. Nil disables portal detection
	// entirely, which is the right thing for a run with no network of its own
	// to probe with.
	Portal Prober
	// RequireCapture says this run cannot work alongside a full-tunnel VPN:
	// TUN mode, whose capture routes a full tunnel overrides. In proxy mode it
	// is false, because a proxy on loopback keeps working underneath any VPN.
	RequireCapture bool

	Clock       Clock
	Debounce    time.Duration
	MaxDebounce time.Duration
	SleepTick   time.Duration
	SleepGap    time.Duration
	PortalPoll  time.Duration
	StepBudget  time.Duration
	SourceRetry time.Duration

	Handler Handler
	Logf    func(string, ...any)
}

// ErrNoFacts and ErrNoNetID are configuration errors, returned by New.
var (
	ErrNoFacts = errors.New("netwatch: Options.Facts is required")
	ErrNoNetID = errors.New("netwatch: Options.NetID is required")
)

// Watcher is the loop. One per process.
type Watcher struct {
	o     Options
	clock Clock
	sleep *SleepDetector

	mu       sync.Mutex
	id       policy.NetworkID
	uplink   string
	portal   Portal
	holds    map[string]bool
	lastErr  error
	settles  int
	reverify int
	probes   int
	// lastProbe rate-limits the canary on the cheap path. Routing churn that
	// does not change the network still costs a re-verify, but three HTTP
	// requests per burst of kernel messages would make dpb the noisiest client
	// on the network for no new information.
	lastProbe time.Time
}

// New validates the options and returns a Watcher that has not started.
func New(o Options) (*Watcher, error) {
	if o.Facts == nil {
		return nil, ErrNoFacts
	}
	if o.NetID == nil {
		return nil, ErrNoNetID
	}
	setd(&o.Debounce, DefaultDebounce)
	setd(&o.MaxDebounce, DefaultMaxDebounce)
	setd(&o.SleepTick, DefaultSleepTick)
	setd(&o.SleepGap, DefaultSleepGap)
	setd(&o.PortalPoll, DefaultPortalPoll)
	setd(&o.StepBudget, DefaultStepBudget)
	setd(&o.SourceRetry, DefaultSourceRetry)
	if o.MaxDebounce < o.Debounce {
		o.MaxDebounce = o.Debounce
	}
	clock := o.Clock
	if clock == nil {
		clock = RealClock()
	}
	return &Watcher{
		o:     o,
		clock: clock,
		sleep: &SleepDetector{Gap: o.SleepGap},
		id:    o.Initial,
		holds: map[string]bool{},
	}, nil
}

func setd(d *time.Duration, def time.Duration) {
	if *d <= 0 {
		*d = def
	}
}

func (w *Watcher) logf(format string, a ...any) {
	if w.o.Logf != nil {
		w.o.Logf(format, a...)
	}
}

// NetID is the namespace the watcher currently believes is in force.
func (w *Watcher) NetID() policy.NetworkID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.id
}

// Portal is the last portal verdict.
func (w *Watcher) Portal() Portal {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.portal
}

// Holds lists the suspensions the watcher is currently holding, sorted for a
// stable rendering.
func (w *Watcher) Holds() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.holds))
	for _, r := range []string{ReasonUplink, ReasonPortal, ReasonSettling} {
		if w.holds[r] {
			out = append(out, r)
		}
	}
	return out
}

// Stats reports how much work the watcher has done. It exists so a test can
// assert that a burst of churn produced exactly one settle, and so `dpb
// status` can show a laptop that is thrashing.
type Stats struct {
	Settles    int
	Reverifies int
	Probes     int
	LastErr    error
}

func (w *Watcher) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{Settles: w.settles, Reverifies: w.reverify, Probes: w.probes, LastErr: w.lastErr}
}

// Run watches until ctx is done, or until a full-tunnel VPN makes the run
// impossible. It returns nil on ctx cancellation and ErrFullTunnelVPN on the
// refuse-for-safety exit.
//
// It never returns because a step failed. A watcher that gave up on the first
// scutil timeout would leave the process believing whatever it believed at
// start-up for the rest of its life, which is worse than a watcher that
// retries.
func (w *Watcher) Run(ctx context.Context) error {
	raw := make(chan struct{}, 1)
	// The source runs on a context of its own so that returning from Run —
	// which the fatal-VPN branch does while ctx is still live — takes the
	// reader down with it instead of parking a goroutine on a socket for the
	// life of the process.
	sctx, scancel := context.WithCancel(ctx)
	srcDone := w.startSource(sctx, raw)
	defer func() {
		scancel()
		<-srcDone
	}()

	var (
		pending  <-chan time.Time
		firstRaw time.Time
		deadline time.Time
		portal   <-chan time.Time
	)
	tick := w.clock.After(w.o.SleepTick)
	w.sleep.Reset(w.clock.Now())

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-raw:
			now := w.clock.Now().Mono
			if pending == nil {
				firstRaw = now
				deadline = now.Add(w.o.Debounce)
				pending = w.clock.After(w.o.Debounce)
				continue
			}
			// Extend the quiet window, but never past the cap: a link that
			// flaps once a second would otherwise postpone the settle forever.
			deadline = now.Add(w.o.Debounce)
			if limit := firstRaw.Add(w.o.MaxDebounce); deadline.After(limit) {
				deadline = limit
			}

		case <-pending:
			now := w.clock.Now().Mono
			if now.Before(deadline) {
				pending = w.clock.After(deadline.Sub(now))
				continue
			}
			pending = nil
			if err := w.onChange(ctx, KindRouteChange, ""); err != nil {
				return err
			}
			portal = w.portalTimer(portal)

		case <-tick:
			tick = w.clock.After(w.o.SleepTick)
			gap := w.sleep.Observe(w.clock.Now())
			if gap <= 0 {
				continue
			}
			w.emit(Event{
				Kind: KindWake, At: w.clock.Now().Wall, Gap: gap,
				Detail: fmt.Sprintf("the wall clock ran %s further than the monotonic clock, "+
					"so the machine slept", gap.Round(time.Second)),
			})
			// Wake is the SECONDARY signal (docs/PLAN.md's exit-path table):
			// the routing churn on wake is primary and usually arrives first,
			// in which case this settle finds nothing changed and costs one
			// re-verify.
			if err := w.onChange(ctx, KindWake, ""); err != nil {
				return err
			}
			portal = w.portalTimer(portal)

		case <-portal:
			portal = nil
			w.repoll(ctx)
			portal = w.portalTimer(portal)
		}
	}
}

// startSource runs the routing-socket reader, re-opening it after a failure.
//
// A bare `go` is legal here — netwatch is not one of the connection-path
// packages the no-bare-goroutine gate covers — but flow.Safe is used anyway so
// that a panic in a kernel-message parser kills the watcher and not the user's
// proxy. The watcher then runs on the sleep ticker alone, which is degraded
// but not blind.
func (w *Watcher) startSource(ctx context.Context, raw chan<- struct{}) <-chan struct{} {
	done := make(chan struct{})
	src := w.o.Source
	if src == nil {
		src = newDefaultSource()
	}
	if src == nil {
		close(done)
		return done
	}
	flow.Safe("netwatch/source", w.o.Logf, func() {
		defer close(done)
		for ctx.Err() == nil {
			err := src.Run(ctx, raw)
			if ctx.Err() != nil {
				return
			}
			w.emit(Event{
				Kind: KindError, At: w.clock.Now().Wall, Err: err,
				Detail: "the routing socket stopped; re-opening it, and revalidating " +
					"on the sleep ticker until it is back",
			})
			select {
			case <-ctx.Done():
				return
			case <-w.clock.After(w.o.SourceRetry):
			}
		}
	})
	return done
}

// portalTimer arms the portal re-probe while, and only while, a portal hold is
// in force. A watcher that is not suspended for a portal does not poll.
func (w *Watcher) portalTimer(cur <-chan time.Time) <-chan time.Time {
	if !w.held(ReasonPortal) {
		return nil
	}
	if cur != nil {
		return cur
	}
	return w.clock.After(w.o.PortalPoll)
}

// onChange is the reaction to one debounced change.
func (w *Watcher) onChange(ctx context.Context, cause Kind, detail string) error {
	facts, err := w.collect(ctx)
	if err != nil {
		// Fail open on the datapath, closed on nothing: an unreadable routing
		// table is not evidence that the network changed, so the previous
		// belief stands and the next tick tries again.
		w.setErr(err)
		w.emit(Event{
			Kind: KindError, At: w.clock.Now().Wall, Err: err,
			Detail: "could not re-read the network; keeping the current namespace",
		})
		return nil
	}
	w.setErr(nil)

	if facts.Uplink == "" {
		w.onUplinkLost(ctx)
		return nil
	}
	w.onUplinkBack(ctx, facts.Uplink)

	if v := ClassifyVPN(facts, w.o.RequireCapture); v.Fatal {
		ev := Event{
			Kind: KindVPNFullTunnel, At: w.clock.Now().Wall,
			Iface: v.Iface, Detail: v.Detail,
		}
		w.emit(ev)
		if w.o.Handler.Stop != nil {
			sctx, cancel := context.WithTimeout(context.Background(), w.o.StepBudget)
			w.o.Handler.Stop(sctx, ev, v.Err)
			cancel()
		}
		return v.Err
	} else if v.Present && v.FullTunnel {
		w.emit(Event{
			Kind: KindVPNFullTunnel, At: w.clock.Now().Wall,
			Iface: v.Iface, Detail: v.Detail,
		})
	}

	id := w.o.NetID(facts)
	prev := w.NetID()
	if id.Equal(prev) {
		// Same network, but macOS flushes interface routes on a link change,
		// so what we applied may be gone. Re-verify without quiescing: there
		// is no namespace to swap and no reason to stop deciding.
		w.emit(Event{
			Kind: cause, At: w.clock.Now().Wall, Uplink: facts.Uplink,
			Detail: detail,
		})
		w.doReverify(ctx)
		w.probePortal(ctx, false)
		return nil
	}

	ev := Event{
		Kind: KindNetworkChange, At: w.clock.Now().Wall,
		NetID: id, Prev: prev, Uplink: facts.Uplink,
		Detail: fmt.Sprintf("the verdict namespace moved from %s to %s", prev.Key(), id.Key()),
	}
	w.settle(ctx, ev, id)
	return nil
}

// settle is the network-change sequence, in the order docs/PLAN.md's exit-path
// table specifies: quiesce, swap the namespace, re-verify every applied Op,
// re-run the portal probe, resume.
//
// The suspension is taken BEFORE the namespace swap and released after, so
// there is no instant in which a connection is judged against a namespace that
// does not describe the network it is about to be sent over.
func (w *Watcher) settle(ctx context.Context, ev Event, id policy.NetworkID) {
	w.hold(ctx, ReasonSettling, ev)
	w.emit(ev)

	w.step(ctx, func(c context.Context) {
		if w.o.Handler.Quiesce != nil {
			w.o.Handler.Quiesce(c, ev)
		}
	})

	w.mu.Lock()
	w.id = id
	w.settles++
	w.mu.Unlock()
	w.step(ctx, func(c context.Context) {
		if w.o.Handler.Namespace != nil {
			w.o.Handler.Namespace(c, id)
		}
	})

	w.doReverify(ctx)
	// Forced: a new network is exactly when the answer can have changed, and
	// the rate limit must not swallow the probe that matters most.
	w.probePortal(ctx, true)

	w.step(ctx, func(c context.Context) {
		if w.o.Handler.Resume != nil {
			w.o.Handler.Resume(c, ev)
		}
	})
	// Released last: a portal hold taken by probePortal above must outlive it.
	w.release(ctx, ReasonSettling, ev)
}

func (w *Watcher) doReverify(ctx context.Context) {
	if w.o.Handler.Reverify == nil {
		return
	}
	w.mu.Lock()
	w.reverify++
	w.mu.Unlock()
	w.step(ctx, func(c context.Context) {
		if err := w.o.Handler.Reverify(c); err != nil {
			w.setErr(err)
			w.emit(Event{
				Kind: KindError, At: w.clock.Now().Wall, Err: err,
				Detail: "some system settings could not be re-applied after the network changed",
			})
		}
	})
}

func (w *Watcher) onUplinkLost(ctx context.Context) {
	if w.held(ReasonUplink) {
		return
	}
	ev := Event{
		Kind: KindUplinkLost, At: w.clock.Now().Wall,
		Detail: "no default route: the capture state is taken down and dpb waits",
	}
	w.hold(ctx, ReasonUplink, ev)
	w.emit(ev)
}

func (w *Watcher) onUplinkBack(ctx context.Context, iface string) {
	if !w.held(ReasonUplink) {
		return
	}
	ev := Event{Kind: KindUplinkBack, At: w.clock.Now().Wall, Uplink: iface}
	w.release(ctx, ReasonUplink, ev)
	w.emit(ev)
}

// probePortal runs the canary once and takes or releases the portal hold.
//
// force skips the rate limit. It is set for the two events that can actually
// change the answer — joining a different network, and polling while
// suspended — and cleared for ordinary churn on a network we are already on.
func (w *Watcher) probePortal(ctx context.Context, force bool) {
	if w.o.Portal == nil {
		return
	}
	now := w.clock.Now().Mono
	w.mu.Lock()
	recent := !w.lastProbe.IsZero() && now.Sub(w.lastProbe) < w.o.PortalPoll
	if !force && recent {
		w.mu.Unlock()
		return
	}
	w.lastProbe = now
	w.probes++
	w.mu.Unlock()

	pctx, cancel := context.WithTimeout(ctx, w.o.StepBudget)
	p := w.o.Portal.Probe(pctx)
	cancel()

	w.mu.Lock()
	w.portal = p
	w.mu.Unlock()

	switch {
	case p.Behind && !w.held(ReasonPortal):
		ev := Event{Kind: KindPortalDetected, At: w.clock.Now().Wall, Portal: p, Detail: p.Detail}
		w.hold(ctx, ReasonPortal, ev)
		w.emit(ev)
	case !p.Behind && w.held(ReasonPortal):
		ev := Event{Kind: KindPortalCleared, At: w.clock.Now().Wall, Portal: p, Detail: p.Detail}
		w.release(ctx, ReasonPortal, ev)
		w.emit(ev)
	}
	// A probe that could not decide (p.Behind false, p.Err set) never takes
	// the hold and never releases one: absence of evidence is not evidence
	// that the portal cleared, and it is certainly not evidence that one
	// appeared. See Portal.Behind.
}

// repoll re-probes while suspended for a portal, and re-verifies when it
// clears: the settings we own were applied to a network the portal was
// intercepting, and the login may have reconfigured DNS underneath us.
func (w *Watcher) repoll(ctx context.Context) {
	was := w.held(ReasonPortal)
	w.probePortal(ctx, true)
	if was && !w.held(ReasonPortal) {
		w.doReverify(ctx)
	}
}

// step runs one hook under the step budget, on a context derived from ctx so
// that shutdown interrupts a hung scutil.
func (w *Watcher) step(ctx context.Context, fn func(context.Context)) {
	c, cancel := context.WithTimeout(ctx, w.o.StepBudget)
	defer cancel()
	fn(c)
}

func (w *Watcher) collect(ctx context.Context) (*netstate.Facts, error) {
	c, cancel := context.WithTimeout(ctx, w.o.StepBudget)
	defer cancel()
	f, err := w.o.Facts(c)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, errors.New("netwatch: fact collection returned nothing")
	}
	return f, nil
}

func (w *Watcher) held(reason string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.holds[reason]
}

func (w *Watcher) hold(ctx context.Context, reason string, ev Event) {
	w.mu.Lock()
	if w.holds[reason] {
		w.mu.Unlock()
		return
	}
	w.holds[reason] = true
	w.mu.Unlock()
	w.logf("netwatch: suspending: %s", ReasonText(reason))
	if w.o.Handler.Suspend != nil {
		w.step(ctx, func(c context.Context) { w.o.Handler.Suspend(c, reason, ev) })
	}
}

func (w *Watcher) release(ctx context.Context, reason string, ev Event) {
	w.mu.Lock()
	if !w.holds[reason] {
		w.mu.Unlock()
		return
	}
	delete(w.holds, reason)
	w.mu.Unlock()
	w.logf("netwatch: lifting: %s", ReasonText(reason))
	if w.o.Handler.Unsuspend != nil {
		w.step(ctx, func(c context.Context) { w.o.Handler.Unsuspend(c, reason, ev) })
	}
}

func (w *Watcher) setErr(err error) {
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
}

func (w *Watcher) emit(ev Event) {
	if ev.At.IsZero() {
		ev.At = w.clock.Now().Wall
	}
	w.logf("netwatch: %s", ev)
	if w.o.Handler.Observe != nil {
		w.o.Handler.Observe(ev)
	}
}
