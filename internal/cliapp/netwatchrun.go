package cliapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/netwatch"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// startNetwatch wires the laptop-reality layer to this run.
//
// It is the answer to "what happens when the laptop moves". Everything it can
// do is already built: the verdict namespace is a box the scope engine reads
// per connection, the kill switch takes named holds, netstate can re-verify
// what it applied, and the resolver chain can drop its answers. This function
// is the ten lines that connect them to the routing socket.
//
// A failure to start is NOT fatal. Losing the watcher costs revalidation on a
// network change — the process keeps working with the namespace it started
// with, which is right for as long as the machine stays on one network — and
// taking away a working proxy to punish an unopenable routing socket would be
// the wrong trade. It is returned as a note so the banner says so.
func startNetwatch(g *globals, f runFlags, sub *subsystems, sys *systemHalf,
	ks *killSwitch, env netstate.Env, live *liveState, st *stack) (notes []string) {

	o := netwatch.Options{
		Facts: func(c context.Context) (*netstate.Facts, error) {
			// factsOf is the same best-effort collector start-up used, so the
			// namespace computed here is computed exactly as the first one was.
			f := g.factsOf(c, env)
			if f == nil {
				return nil, errors.New("the machine's network identity could not be read")
			}
			return f, nil
		},
		NetID: func(f *netstate.Facts) policy.NetworkID {
			return networkID(f, sub.resolvers)
		},
		Initial:        sub.netID.get(),
		Portal:         portalProbe(sub),
		RequireCapture: requiresCapture(f),
		Handler:        netwatchHandler(g, sub, sys, ks, live),
		Logf:           g.logf,
	}
	if g.netwatchOpts != nil {
		g.netwatchOpts(&o)
	}
	w, err := netwatch.New(o)
	if err != nil {
		return []string{fmt.Sprintf(
			"the network watcher did not start (%v), so a change of network will not "+
				"swap the verdict namespace until dpb is restarted", err)}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	flow.Safe("cliapp/netwatch", g.logf, func() {
		defer close(done)
		if err := w.Run(ctx); err != nil {
			g.logf("run: network watcher: %v", err)
			// The one fatal verdict: a full-tunnel VPN under a run that must
			// capture. It reaches the main loop as a refusal, which is exit
			// code 5 — "understood, and declining for safety" — rather than a
			// process that keeps printing Ready while capturing nothing.
			select {
			case sub.serveErr <- refusedError{err}:
			default:
			}
		}
	})
	// Pushed AFTER the system settings, so it is drained BEFORE them: a
	// watcher still running while teardown reverts would see its own
	// handiwork disappear and put it straight back.
	st.push("stop the network watcher", func(context.Context) error {
		cancel()
		<-done
		return nil
	})
	g.logf("run: watching the routing socket; the verdict namespace is %s", sub.netID.get().Key())
	return nil
}

// requiresCapture says whether this run's correctness depends on owning
// routes, which is what makes a full-tunnel VPN fatal rather than merely
// notable.
//
// Proxy mode does not: a browser reaches 127.0.0.1 without consulting the
// default route, so dpb keeps working underneath any VPN. TUN mode does.
//
// --allow-vpn is deliberately NOT consulted here. It overrides the start-up
// refusal, where the user can see the VPN and has decided the tunnel will not
// own the routes they need; a VPN that comes up LATER, mid-run, is a different
// event, and the honest answer to "the default route just moved to a full
// tunnel" is to stop rather than to keep reporting Ready while capturing
// nothing.
func requiresCapture(f runFlags) bool { return f.tun }

// portalProbe builds the captive-portal canary, or nil when this run has no
// way to probe with.
func portalProbe(sub *subsystems) netwatch.Prober {
	if sub.dial == nil {
		return nil
	}
	return &netwatch.PortalProbe{
		Dial:    sub.dial,
		Resolve: sub.chain.Resolve,
	}
}

// netwatchHandler is what this process does about a change.
func netwatchHandler(g *globals, sub *subsystems, sys *systemHalf,
	ks *killSwitch, live *liveState) netwatch.Handler {

	return netwatch.Handler{
		// Suspend is the quiesce lever, and it is the SAME one `dpb off` and
		// mode = "never" pull: every surface that can escalate reads it, so
		// there is no half of the process still desyncing while the other half
		// believes it stopped. While it is held every flow is ScopeDirect —
		// relayed with nothing buffered, no ladder, no verdict written or
		// read. Traffic keeps flowing; only the judging stops.
		Suspend: func(_ context.Context, reason string, _ netwatch.Event) {
			ks.hold(reason, netwatch.ReasonText(reason))
		},
		Unsuspend: func(_ context.Context, reason string, _ netwatch.Event) {
			ks.release(reason)
		},

		// Quiesce drops what belonged to the old network. The DNS answer cache
		// is the load-bearing one: an address learned from the previous
		// network's resolver is at best stale and at worst that network's
		// sinkhole, and the chain has no other way to withdraw an answer it
		// already served.
		Quiesce: func(context.Context, netwatch.Event) {
			sub.chain.Flush()
		},

		Namespace: func(_ context.Context, id policy.NetworkID) {
			sub.netID.set(id)
		},

		Reverify: func(c context.Context) error {
			if sys == nil {
				return nil // --proxy-style none or --dry-run: nothing was applied
			}
			rep, err := sys.reverify(c)
			for _, r := range rep.Restored {
				g.logf("run: re-applied %s %s after a network change", r.Kind, r.ID)
			}
			if len(rep.Restored) > 0 {
				live.setNotes(append(live.notesCopy(), fmt.Sprintf(
					"%d system setting(s) were flushed by a network change and put back",
					len(rep.Restored))))
			}
			return err
		},

		Resume: func(_ context.Context, ev netwatch.Event) {
			g.logf("run: resumed on %s", ev.NetID.Key())
		},

		Stop: func(_ context.Context, ev netwatch.Event, _ error) {
			g.logger().Warn(
				"stop the VPN, or run dpb in proxy mode, which works underneath a full tunnel",
				"%s", ev.Detail)
		},

		Observe: func(ev netwatch.Event) { observeNetwatch(g, ev) },
	}
}

// observeNetwatch turns a watcher event into the one line a user sees.
//
// A network change and a captive portal are warnings with a remediation
// because they change what dpb is doing; everything else is debug detail.
func observeNetwatch(g *globals, ev netwatch.Event) {
	switch ev.Kind {
	case netwatch.KindPortalDetected:
		remedy := "open http://captive.apple.com in a browser and finish the network's login; " +
			"dpb resumes by itself once it clears"
		if ev.Portal.LoginURL != "" {
			remedy = "open " + ev.Portal.LoginURL + " and finish the network's login; " +
				"dpb resumes by itself once it clears"
		}
		g.logger().Warn(remedy,
			"a captive portal is intercepting this network, so dpb suspended itself and "+
				"every request now goes DIRECT (%s)", ev.Detail)
	case netwatch.KindUplinkLost:
		g.logger().Warn("none needed; dpb resumes when a network comes back",
			"the uplink went away, so dpb suspended itself")
	case netwatch.KindNetworkChange:
		g.logf("run: %s", ev)
	default:
		g.logf("run: %s", ev)
	}
}

// notesCopy is the live state's notes, for a caller that wants to append.
func (l *liveState) notesCopy() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.notes...)
}
