package cliapp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/tunfe"
	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/netwatch"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
)

// TUN mode, wired to the command line.
//
// `--tun` is a flag on `run` rather than a mode of its own because the tunnel
// is ADDITIVE: the proxy listeners, the PAC and the exported environment all
// keep running, and the tunnel picks up the programs that ignore every one of
// them. Proxy mode stays the default for a measured reason, not a cautious one:
// MEASUREMENTS.md §3 records the unprivileged chunk/record emitters beating
// this DPI outright, so root buys coverage of proxy-unaware binaries and
// nothing else.
//
// Everything the tunnel changes about the machine goes through the same
// netstate.Manager the proxy settings do, so there is ONE journal, ONE teardown
// order and one `dpb doctor --repair` that can finish the job after a SIGKILL.
// macOS route(8) reports failure with exit status 0, which is exactly why no
// step here shells out on its own.

const (
	// tunLocal and tunPeer are the utun's point-to-point addresses. A utun
	// needs both: without a peer the kernel has no destination to hang the
	// interface route on.
	//
	// They sit high in 10/8 rather than in 100.64/10 or 198.18/15. Both of
	// those are in use by things a dpb user plausibly runs — Tailscale hands
	// out 100.64/10 addresses, and 198.18/15 is the range the plan rejected
	// fake-IP over precisely because VPNs collide with it — whereas a consumer
	// router that hands out 10.255.90.x is not a shape anyone ships. They are
	// also inside policy's compiled-in bogon table, so a flow addressed to the
	// tunnel itself is a hard bypass and can never be judged or desynced.
	tunLocal = "10.255.90.1"
	tunPeer  = "10.255.90.2"
	// tunLocalV6 is the tunnel's ULA address, used only when this machine has
	// a working IPv6 uplink to escape through. fd00::/8 is the RFC 4193
	// private range; the /48 is arbitrary and fixed so a leftover address is
	// recognisable as ours.
	tunLocalV6 = "fd70:db9:f4ce::1"
)

// requireRootForTun is exit code 4 with a message that says what to do.
//
// The published contract (docs/PLAN.md's CLI surface) gives 4 exactly one
// meaning, "needs root", and the LaunchAgent branches on it, so this is the
// same codedError `dpb service install --system` returns.
func requireRootForTun(layout paths.Layout, dryRun bool) error {
	if layout.Elevated {
		return nil
	}
	if dryRun {
		// --dry-run applies nothing, so it needs nothing. Printing the exact
		// sequence a root run would apply is the one useful thing an
		// unprivileged user can do with --tun, and refusing it would make the
		// safest way to inspect this mode the one that needs sudo.
		return nil
	}
	return codedError{
		code: ExitNeedRoot,
		err: errors.New("--tun opens a utun device and rewrites this machine's routing table, " +
			"which macOS permits only to root.\n" +
			"  Re-run it as:      sudo dpb run --tun\n" +
			"  See what it would change first, with no sudo and no mutation:\n" +
			"                     dpb run --tun --dry-run\n" +
			"  Or drop --tun: `dpb run` needs no root at all, and the emitters measured\n" +
			"  beating this DPI are all reachable from an unprivileged socket. The tunnel\n" +
			"  adds coverage of programs that ignore proxy settings, not new techniques"),
	}
}

// refuseFullTunnelVPN is the M15 gate that could not be reached until --tun
// existed: ErrFullTunnelVPN, exit code 5.
//
// The netwatch watcher applies the same rule on every later network change.
// This is the one at start-up, because the watcher classifies on a CHANGE and a
// VPN that was already up when dpb started produces no change to classify.
func refuseFullTunnelVPN(facts *netstate.Facts, tun, allowVPN bool) error {
	v := netwatch.ClassifyVPN(facts, tun)
	if !v.Fatal {
		return nil
	}
	if allowVPN {
		return nil
	}
	return refusedError{fmt.Errorf("%w.\n"+
		"  %s\n"+
		"  Stop the VPN, or run `dpb run` without --tun: a loopback proxy keeps working\n"+
		"  underneath a full tunnel, because a browser reaches 127.0.0.1 without consulting\n"+
		"  the default route at all. `--allow-vpn` overrides this if you know the tunnel\n"+
		"  will not own the routes you need",
		netwatch.ErrFullTunnelVPN, v.Detail)}
}

// validTunName matches the only device names macOS will ever hand this tool:
// "utun" (the kernel picks a free unit) or "utunN".
var validTunName = regexp.MustCompile(`^utun(0|[1-9][0-9]{0,3})?$`)

// validateTunName refuses a --tun-name that is not a utun.
//
// `--tun-name en0` used to be ACCEPTED, and under --dry-run it printed a plan
// that would ifconfig the machine's real uplink, hang the capture routes off it
// and point the system resolvers at it. Nothing was applied, so nobody was
// endangered — but the printed plan was a lie about what the tool would do, and
// --dry-run's only job is to describe exactly that.
//
// The check is a name check and nothing more: it opens no device and reads no
// interface, so it behaves identically as root, unprivileged and under
// --dry-run. Whether a given utun unit is free is the kernel's answer to give,
// and it gives it at open time.
func validateTunName(name string) error {
	if validTunName.MatchString(name) {
		return nil
	}
	return usagef("run: --tun-name %q: a tunnel device on macOS is \"utun\" or \"utunN\", and "+
		"dpb opens one of its own rather than attaching to an interface that already exists.\n"+
		"  %q is the name of a real interface on this machine or of something that is not a "+
		"utun at all; configuring it and routing the whole address space through it is not "+
		"something dpb will describe, let alone do.\n"+
		"  Drop --tun-name to let the kernel pick a free unit, which is the default and what "+
		"every route and ifconfig step is then told about", name, name)
}

// resolveSetDNS decides whether this run points the system's resolvers at us.
//
// docs/PLAN.md: off in proxy mode, on under --tun. Proxy mode does not need it
// — a proxied client hands us the name inside CONNECT — and turning it on there
// would double the unprivileged blast radius for nothing, which is why the
// config key still refuses.
func resolveSetDNS(tun bool, flag string) (bool, error) {
	switch flag {
	case "":
		return tun, nil
	case "on":
		if !tun {
			return false, usagef("run: --set-dns on is a TUN-mode setting. In proxy mode the " +
				"client hands us the name inside CONNECT or the SOCKS5 request, so nothing " +
				"has to be pointed anywhere; add --tun, or drop --set-dns")
		}
		return true, nil
	case "off":
		return false, nil
	default:
		return false, usagef("run: --set-dns %q: want off or on", flag)
	}
}

// tunUplink is the interface our own upstream sockets are pinned to.
//
// It is fatal in TUN mode and only in TUN mode. The capture routes cover the
// whole address space, so a socket that is not pinned to a real uplink is
// routed back into our own netstack; without a name to pin to there is no way
// to build a tunnel that can reach anything, and starting one anyway would be
// the blackhole the banner exists to make impossible.
func tunUplink(f *netstate.Facts) (string, error) {
	if f == nil || f.Uplink == "" {
		return "", errors.New("run: --tun needs the name of this machine's uplink interface, and the " +
			"routing table did not name one. Check `route -n get default` and `ifconfig -a`: " +
			"with no default route there is nothing for dpb's own upstream sockets to escape " +
			"through, and every one of them would be captured by dpb's own tunnel")
	}
	return f.Uplink, nil
}

// tunHalf is the running tunnel, kept so the banner and `dpb status` can
// describe it. It is nil when this run has no tunnel.
type tunHalf struct {
	iface string
	srv   *tunfe.Server
}

// startTun opens the device, builds the datapath and applies the system state,
// in the order docs/PLAN.md data path F specifies.
//
// The teardown step is pushed BEFORE bring-up starts, so a bring-up that fails
// on its fourth route unwinds the three that landed. It is pushed after the
// proxy settings, which means it drains before them: routes come off while the
// listeners those settings point at are still up.
// setDNS is resolved by runRun rather than here: resolveSetDNS is a usage gate
// as well as a default, and a gate that lives on the --tun path alone cannot
// refuse the flag in the mode it is invalid in.
func startTun(ctx context.Context, g *globals, cfg *config.Loaded, f runFlags, setDNS bool,
	sub *subsystems, inner tunfe.Sequencer, env netstate.Env, st *stack) (
	half *tunHalf, applied, notes []string, err error) {

	// Everything the tunnel changes is reported the way the proxy half is:
	// only after the Op applied AND was independently verified. The banner
	// promises "Ctrl-C reverts every change above", and a change the banner
	// does not list is a change the user was never told about.
	seq := &appliedSeq{Sequencer: inner}

	// Before anything is built, described or opened: a plan that names the
	// wrong device is not worth printing.
	if err := validateTunName(f.tunName); err != nil {
		return nil, nil, nil, err
	}

	uplink, err := tunUplink(env.Facts)
	if err != nil {
		return nil, nil, nil, err
	}
	mtu := f.mtu
	if mtu <= 0 {
		mtu = tunfe.DefaultMTU
	}

	// --dry-run opens no device. The point of the flag is to print what would
	// be changed without changing anything, and a utun is a change: it appears
	// in `ifconfig -a` and it needs root. The Ops below are still built and
	// still handed to the Manager, which logs each one and applies none, so the
	// ORDER — the part of this that is actually hard — is inspectable without
	// sudo.
	var (
		link  tunfe.Link
		srv   *tunfe.Server
		iface = f.tunName
	)
	if !f.dryRun {
		l, err := g.openLinkOf()(f.tunName, mtu, g.logf)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("run: --tun: open %s: %w", f.tunName, err)
		}
		link = l
		// The kernel picks the unit for "utun", so the name every route and
		// ifconfig Op is told must come from the device and never from the
		// name that was requested.
		name, err := l.Name()
		if err != nil {
			_ = l.Close()
			return nil, nil, nil, fmt.Errorf("run: --tun: read the device name: %w", err)
		}
		iface = name

		srv, err = tunfe.New(tunOptions(g, cfg, sub, l, mtu))
		if err != nil {
			_ = l.Close()
			return nil, nil, nil, fmt.Errorf("run: --tun: build the datapath: %w", err)
		}
	}

	capt := tunfe.Capture{
		Iface:   iface,
		Local:   netip.MustParseAddr(tunLocal),
		Peer:    netip.MustParseAddr(tunPeer),
		MTU:     mtu,
		Uplink:  uplink,
		Gateway: gatewayOf(env.Facts),
		V6Gate:  sub.v6gate,
		// Runner is deliberately left nil: every Op then executes through the
		// Manager's own Env, so there is exactly one runner for the run and a
		// journalled Op revived by `dpb doctor --repair` in a LATER process
		// runs the same way this one did.
		Logf: g.logf,
	}
	if capturesV6(env.Facts) {
		capt.LocalV6 = netip.MustParseAddr(tunLocalV6)
		capt.GatewayV6 = env.Facts.GatewayV6
	}

	// The machine's own resolvers: /32 host routes so their traffic is captured
	// rather than escaping down the uplink's subnet route, and the fail-open
	// tail of the list we point the services at.
	prior := systemNameservers(ctx, env)
	capt.Nameservers = prior
	if setDNS {
		capt.Services = servicesOf(env.Facts)
		capt.Resolvers = tunResolverList(prior)
		if len(capt.Services) == 0 {
			// networksetup needs a service to configure. An empty list makes
			// the Op ask macOS for every enabled service itself, which is the
			// right fallback, so this is a note and not a failure.
			g.logf("run: --tun: no named network service; the DNS Op will enumerate them itself")
		}
	}

	// stopDatapath is written by start (on the bring-up goroutine) and read by
	// the teardown step (which a signal handler can run on another), so it is
	// guarded. The two are far apart in wall-clock time and would almost never
	// collide, which is exactly the kind of race that is only ever seen on a
	// user's laptop.
	var (
		stopMu       sync.Mutex
		stopDatapath func()
	)
	half = &tunHalf{iface: iface, srv: srv}

	// Pushed before a single Op runs. A bring-up that dies halfway must unwind
	// what it managed to apply, and this is the only registration that survives
	// a signal or a panic arriving mid-bring-up.
	st.push("tear down the tunnel", func(c context.Context) error {
		stop := func() {
			stopMu.Lock()
			fn := stopDatapath
			stopMu.Unlock()
			if fn != nil {
				fn()
			}
			if srv != nil {
				// What the tunnel actually carried. A user who ran with sudo
				// and saw nothing change needs to be able to tell "the tunnel
				// was never in the path" from "the tunnel carried the traffic
				// and it still failed", and these are the only numbers that
				// answer it.
				st := srv.Stats()
				g.logf("run: tunnel %s carried %d TCP flow(s), %d UDP, %d DNS; "+
					"%d refused, %d failed, %d escalated (%d packets in, %d out, %d read errors)",
					iface, st.TCPFlows, st.UDPFlows, st.DNSFlows,
					st.Refused, st.Failed, st.Escalated,
					st.PacketsIn, st.PacketsOut, st.ReadErrors)
				srv.Close()
			}
		}
		return errors.Join(capt.TearDown(c, seq, stop, link)...)
	})

	start := func(context.Context) error {
		if srv == nil {
			return nil
		}
		sctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		stopMu.Lock()
		stopDatapath = func() {
			cancel()
			<-done
		}
		stopMu.Unlock()
		flow.Safe("cliapp/tun", g.logf, func() {
			defer close(done)
			// Serve returns nil for a cancelled context and the device's error
			// otherwise. A device error is not recoverable: the capture routes
			// still point at this device, so the whole run has to come down
			// rather than keep printing Ready over a link that reads nothing.
			if err := srv.Serve(sctx); err != nil {
				// Into the channel runRun's main loop selects on, so the
				// process comes down. A device that stopped reading while the
				// capture routes still point at it is a blackhole, and a
				// blackhole that keeps printing Ready is the exact failure the
				// banner's verified-facts rule exists to prevent.
				g.serveFailed(sub.serveErr,
					fmt.Errorf("run: the tunnel datapath stopped: %w", err))
			}
		})
		return nil
	}

	if err := capt.BringUp(ctx, seq, start); err != nil {
		return nil, nil, nil, err
	}

	if !setDNS {
		notes = append(notes, "--set-dns off: the system resolver list was left alone; "+
			"queries to the resolvers it already names are still answered in the tunnel")
	}
	if !capt.LocalV6.IsValid() {
		notes = append(notes, "IPv6 is not captured (this machine has no IPv6 default route), "+
			"so AAAA answers are suppressed with NOERROR and an SOA rather than handing out "+
			"addresses nothing is protecting")
	}
	g.logf("run: tunnel %s is up on %s -> %s, escaping through %s", iface, tunLocal, tunPeer, uplink)
	return half, seq.list(), notes, nil
}

// appliedSeq records what actually landed.
//
// It wraps the run's Manager rather than replacing it: the Op still goes
// through the same journal, the same independent verification and the same
// UndoAll. All this adds is the list the banner prints, and it appends only
// after Do returned nil — so a route that route(8) claimed to install and the
// RIB says is absent is reported as a failure, not as an applied change.
type appliedSeq struct {
	tunfe.Sequencer
	mu   sync.Mutex
	done []string
}

func (a *appliedSeq) Do(ctx context.Context, op netstate.Op) error {
	if err := a.Sequencer.Do(ctx, op); err != nil {
		return err
	}
	a.mu.Lock()
	a.done = append(a.done, op.Describe())
	a.mu.Unlock()
	return nil
}

func (a *appliedSeq) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.done...)
}

// tunOptions is the tunnel's datapath, built out of the objects proxy mode is
// already using.
//
// It is a function of its own because that identity IS the design: there is one
// ladder runner, one scope engine, one reverse map, one resolver, one small-write
// governor and one event sink for the whole process, and TUN mode is handed all
// six rather than given a set of its own. Two consequences the previous
// implementation got wrong fall straight out of it — a user who excluded their
// bank keeps that exclusion when the flow arrives as a bare address under sudo,
// because Reverse is the same map the DNS answers were learned into; and the
// tunnel cannot reach a different verdict from the proxy about the same host,
// because there is no second decision path to reach it with.
func tunOptions(g *globals, cfg *config.Loaded, sub *subsystems, link tunfe.Link, mtu int) tunfe.Options {
	return tunfe.Options{
		Link:   link,
		MTU:    mtu,
		Scope:  sub.scope,
		Ladder: sub.runner,
		// Pinned to the uplink, so our own upstream sockets escape the capture
		// routes that cover the whole address space.
		UDPDial:   sub.udpDial,
		Reverse:   sub.reverse,
		DNS:       sub.dns,
		Sender:    sub.sender,
		FirstMsg:  firstMsgOpts(cfg),
		RelayIdle: cfg.IdleTimeout.D(),
		OnConn:    sub.onConn,
		Logf:      g.logf,
	}
}

// gatewayOf is the machine's real v4 next hop, which the interface-scoped
// default route is built from.
func gatewayOf(f *netstate.Facts) netip.Addr {
	if f == nil {
		return netip.Addr{}
	}
	return f.Gateway
}

func servicesOf(f *netstate.Facts) []string {
	if f == nil {
		return nil
	}
	return append([]string(nil), f.Services...)
}

// capturesV6 says whether this machine has an IPv6 path worth capturing.
//
// It is deliberately conservative. Capturing ::/1 and 8000::/1 on a v4-only
// machine would install routes nothing can use and, worse, would open the
// IPv6Gate — which is the resolver's licence to hand applications AAAA records.
// No v6 gateway means no escape route for our own v6 sockets, so the honest
// answer is that IPv6 is not protected here.
func capturesV6(f *netstate.Facts) bool {
	return f != nil && f.GatewayV6.IsValid() && len(f.V6Global) > 0
}

// systemNameservers reads what this machine resolves with today.
//
// They are read through `scutil --dns`, the same observer netstate's DNS Op
// verifies with, so the addresses we install host routes for are the addresses
// mDNSResponder is actually using — not the ones a plist says it should.
// Loopback entries are dropped: a /32 route for 127.0.0.1 into the tunnel would
// capture the user's own local resolver, and a run that died would leave the
// services pointed at an address that answers nothing.
func systemNameservers(ctx context.Context, env netstate.Env) []netip.Addr {
	rs, err := netstate.ReadDNSResolvers(ctx, env)
	if err != nil {
		env.Logf("run: --tun: read the system resolvers: %v", err)
		return nil
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, s := range netstate.PrimaryNameservers(rs) {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.IsLoopback() || a.IsUnspecified() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// tunResolverList is what the network services are pointed at: the tunnel
// first, then the machine's own resolvers behind it.
//
// The tail is the deliberate fail-OPEN half of the design. A dpb that is
// SIGKILLed takes its capture routes with it eventually, but until the janitor
// or the login agent gets there, a services list naming only the tunnel would
// leave a banking laptop with no DNS at all and no attributable error. Naming
// the originals behind us costs one RTT in that window and nothing at all while
// dpb is alive, because the tunnel answers first.
func tunResolverList(prior []netip.Addr) []string {
	out := []string{tunLocal}
	for _, a := range prior {
		if a.Is4() || a.Is4In6() {
			out = append(out, a.String())
		}
	}
	return out
}
