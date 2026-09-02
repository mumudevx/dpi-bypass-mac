package cliapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
)

// liveState is what a running `dpb run` can say about itself, and the handful
// of levers a second dpb process can pull on it through the control socket.
//
// It exists because `dpb status`, `dpb why`, `dpb on`, `dpb off`, `dpb reload`,
// `dpb panic` and `dpb coverage --fix` all reach the running process the same
// way, and the alternative — each command reading the machine and guessing —
// cannot see a verdict learned since start-up or a setting this process knows
// it failed to apply.
type liveState struct {
	started   time.Time
	cfg       *config.Loaded
	layout    paths.Layout
	ladder    []string
	listeners []listener

	sub      *subsystems
	ks       *killSwitch
	counters *observ.Counters
	sys      *systemHalf

	// stop asks runRun to return. It is sync.OnceFunc: `dpb panic` must be
	// answerable twice without closing a closed channel.
	stop func()
	// reload re-reads the configuration layers and swaps the scope rules. It is
	// a closure because the flags the user typed are only in scope in runRun,
	// and a reload that dropped them would quietly undo half the command line.
	reload func(context.Context) error

	mu      sync.Mutex
	applied []string
	notes   []string
}

func (l *liveState) setNotes(notes []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.notes = append([]string(nil), notes...)
}

func (l *liveState) systemReport() (applied, notes []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.applied...), append([]string(nil), l.notes...)
}

// handler is the control-socket surface. Every command is answered from a fact
// this process observed; nothing here is an intention.
func (l *liveState) handler() observ.Handler {
	return observ.Handler{
		Status:  l.status,
		Why:     whyHandler(l.sub.engine, l.sub.netID.get, l.counters),
		On:      l.on,
		Off:     l.off,
		Reload:  l.doReload,
		Reapply: l.doReapply,
		Panic:   l.panic,
	}
}

func (l *liveState) status(context.Context) (observ.Status, error) {
	suspended, reason := l.ks.state()
	applied, notes := l.systemReport()

	st := observ.Status{
		Running:       true,
		PID:           os.Getpid(),
		Version:       buildinfo.Short(),
		Started:       l.started,
		Profile:       l.cfg.Profile,
		Sources:       l.cfg.Sources,
		Mode:          string(l.cfg.Mode),
		ProxyStyle:    string(l.cfg.ProxyStyle),
		Suspended:     suspended,
		SuspendReason: reason,
		Applied:       applied,
		Notes:         notes,
		Strategy:      l.cfg.Strategy,
		Ladder:        append([]string(nil), l.ladder...),
		Resolvers:     resolverHealth(l.sub.chain.Health()),
		NetworkID:     l.sub.netID.get().Key(),
		Conns:         l.counters.Snapshot(),
	}
	for _, ln := range l.listeners {
		st.Listeners = append(st.Listeners, observ.Listener{Kind: ln.Kind, Addr: ln.Addr})
	}
	// The tuned profile and the verdict cache are on disk, so they are read
	// here rather than remembered: `dpb apply` can write a profile while this
	// process runs, and reporting the one loaded at start-up would be a lie
	// with a timestamp on it.
	st.Tuned = tunedStatus(l.layout, l.sub.netID.get().Key())
	st.Cache = cacheStatus(l.layout, l.cfg, l.sub.netID.get())
	return st, nil
}

// resolverHealth flattens the chain's per-rung health onto the wire type.
//
// A rung that was never tried reports OK=false with a nil Err, and that has to
// survive the conversion: `dpb status` renders it as "untried", and a chain
// that answered on rung 1 has told us nothing about rung 5.
func resolverHealth(hs []resolve.Health) []observ.ResolverHealth {
	if len(hs) == 0 {
		return nil
	}
	out := make([]observ.ResolverHealth, 0, len(hs))
	for _, h := range hs {
		row := observ.ResolverHealth{
			Label:    h.Label,
			OK:       h.OK,
			Tried:    h.OK || h.Err != nil,
			Latency:  h.Latency,
			Sinkhole: h.Signal.Sinkhole,
		}
		if h.Err != nil {
			row.Err = h.Err.Error()
		}
		out = append(out, row)
	}
	return out
}

func (l *liveState) on(context.Context) error {
	l.ks.set(false, "")
	return nil
}

func (l *liveState) off(context.Context) error {
	l.ks.set(true, "`dpb off`")
	return nil
}

func (l *liveState) doReload(ctx context.Context) error {
	if l.reload == nil {
		return errors.New("cliapp: this dpb cannot reload its configuration")
	}
	return l.reload(ctx)
}

// doReapply re-asserts the system proxy settings this run owns.
//
// It is what `dpb coverage --fix` sends, and only this process can do it: the
// settings name THIS run's listener ports, so a second dpb re-writing them
// would point macOS at a port nothing is listening on.
func (l *liveState) doReapply(context.Context) error {
	if l.sys == nil {
		return errors.New(
			"this dpb changed no system settings (--proxy-style none or --dry-run), " +
				"so there is nothing to re-apply")
	}
	// A fresh context, never the request's: every netstate Op checks ctx.Err()
	// before it journals, and a client that hung up mid-exchange would
	// otherwise leave half the settings written and none of them recorded.
	ctx, cancel := context.WithTimeout(context.Background(), teardownBudget)
	defer cancel()

	applied, notes := l.sys.reapply(ctx)
	l.mu.Lock()
	l.applied = applied
	l.notes = notes
	l.mu.Unlock()

	if len(applied) == 0 && len(notes) > 0 {
		return fmt.Errorf("nothing could be re-applied: %s", strings.Join(notes, "; "))
	}
	return nil
}

// panic reverts every system change and asks the process to stop.
//
// It reverts HERE rather than leaving it to the teardown stack because the
// contract is that the reply reaches the client after the revert is done: a
// user who types `dpb panic` and sees "reverted" needs that to be a report, not
// a promise. Stopping the process is left to runRun's main loop so the response
// is written before anything closes.
func (l *liveState) panic(context.Context) error {
	var err error
	if l.sys != nil {
		ctx, cancel := context.WithTimeout(context.Background(), teardownBudget)
		defer cancel()
		err = l.sys.revert(ctx)
	}
	if l.stop != nil {
		l.stop()
	}
	return err
}
