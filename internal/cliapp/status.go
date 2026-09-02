package cliapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// `dpb status` is the first thing a user types when "nothing works".
//
// It has to be answerable in both directions. With a dpb running it reports
// what that process observed — which listeners are up, which system settings
// were VERIFIED (not attempted), which resolvers answered, what the ladder has
// been doing, and whether the escalation rate says the ISP changed its DPI.
// With no dpb running it still has to say something true: whether one died
// holding the run lock, whether the journal has unfinished mutations sitting on
// the machine right now, how old the tuned profile is, and how much the verdict
// cache remembers.
//
// The second half is the one that matters most. A user whose network broke
// after a crash needs to be told that there is residue and that
// `dpb doctor --repair` clears it, and they need to be told by the command they
// would type first.

// statusInterval is how often `--watch` redraws.
const statusInterval = 2 * time.Second

func newStatusCmd(g *globals) *cobra.Command {
	var (
		asJSON bool
		watch  bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report whether dpb is running and what it is doing",
		Long: "status reports the running process if there is one — listeners, verified\n" +
			"system settings, resolver chain health, ladder activity and suspected DPI\n" +
			"drift — and, either way, the state left on this machine: the run lock, any\n" +
			"unfinished system mutations in the journal, the measured profile's age and\n" +
			"the size of the verdict cache.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd.Context(), g, asJSON, watch)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the status as JSON")
	cmd.Flags().BoolVar(&watch, "watch", false, "redraw every "+statusInterval.String()+" until interrupted")
	return cmd
}

func runStatus(ctx context.Context, g *globals, asJSON, watch bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	emitOnce := func() error {
		st, err := buildStatus(ctx, g)
		if err != nil {
			return err
		}
		if asJSON {
			enc := json.NewEncoder(g.env.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(st); err != nil {
				return fmt.Errorf("status: write JSON: %w", err)
			}
			return nil
		}
		return renderStatus(g.env.Stdout, st, time.Now())
	}

	if !watch {
		return emitOnce()
	}
	tick := time.NewTicker(statusInterval)
	defer tick.Stop()
	for {
		if err := emitOnce(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			// A watch that was interrupted did what it was asked to do, so it
			// is not a failure. cmd/dpb turns a cancelled context into exit 1
			// only for commands that returned one.
			return nil
		case <-tick.C:
			fmt.Fprintln(g.env.Stdout)
		}
	}
}

// buildStatus asks the running dpb first and fills the on-disk half either way.
//
// The on-disk half is filled even when the daemon answered, because the two are
// different facts: the daemon reports what IT has applied, and the disk reports
// what is left on the machine, which after a crash includes another run's
// residue the live process knows nothing about.
func buildStatus(ctx context.Context, g *globals) (observ.Status, error) {
	layout, err := g.layoutOf()
	if err != nil {
		return observ.Status{}, err
	}

	st, lerr := g.controlClient(layout).Status(ctx)
	if lerr != nil {
		if !errors.Is(lerr, observ.ErrNotRunning) {
			st.Notes = append(st.Notes,
				fmt.Sprintf("the control socket is there but did not answer: %v", lerr))
		}
		st = offlineStatus(ctx, g, layout, st)
	}
	st.Journal = journalStatus(layout)
	if st.Version == "" {
		st.Version = buildinfo.Short()
	}
	return st, nil
}

// offlineStatus fills in everything that can be learned without the daemon.
func offlineStatus(ctx context.Context, g *globals, layout paths.Layout, st observ.Status) observ.Status {
	st.Running = false

	// The run lock names whoever last held it. A live owner with no reachable
	// control socket is a real and reportable state: the process is up but
	// cannot be talked to, which is a different problem from "not running".
	if info, err := netstate.ReadLock(layout.LockFile()); err == nil && info.PID > 0 {
		if netstate.OwnerAlive(info.PID, info.StartedAt) {
			st.Running = true
			st.PID = info.PID
			st.Started = info.StartedAt
			st.Notes = append(st.Notes, fmt.Sprintf(
				"a dpb (pid %d) holds the run lock but its control socket at %s is not answering",
				info.PID, layout.ControlSocket()))
		} else {
			st.Notes = append(st.Notes, fmt.Sprintf(
				"the last dpb (pid %d) is gone; see the journal line below", info.PID))
		}
	}

	cfg, err := scopeConfig(g)
	if err != nil {
		st.Notes = append(st.Notes, fmt.Sprintf("the configuration could not be loaded: %v", err))
		return st
	}
	st.Profile = cfg.Profile
	st.Sources = cfg.Sources
	st.Mode = string(cfg.Mode)
	st.ProxyStyle = string(cfg.ProxyStyle)
	st.Strategy = cfg.Strategy
	if ladder, lerr := cfg.LadderSpecs(); lerr == nil {
		st.Ladder = ladder
	} else {
		st.Notes = append(st.Notes, fmt.Sprintf("the configured ladder does not parse: %v", lerr))
	}

	netID, nerr := g.networkIdentity(ctx, cfg)
	if nerr != nil {
		st.Notes = append(st.Notes, fmt.Sprintf("the network identity is incomplete: %v", nerr))
	}
	st.NetworkID = netID.Key()
	st.Tuned = tunedStatus(layout, netID.Key())
	st.Cache = cacheStatus(layout, cfg, netID)
	return st
}

// journalStatus reports unfinished system mutations without touching the file.
func journalStatus(layout paths.Layout) observ.JournalStatus {
	js := observ.JournalStatus{Path: layout.JournalFile()}
	pending, err := netstate.ReadPending(js.Path)
	if err != nil {
		js.Err = err.Error()
		return js
	}
	js.Pending = len(pending)
	for _, r := range pending {
		if netstate.OwnerAlive(r.PID, r.StartedAt) {
			js.OwnedByLive++
			continue
		}
		if r.Adopted {
			// Adopted state was never ours; it is pending only because nobody
			// has closed the entry. Counting it as residue would tell a user
			// their VPN's routes need repairing.
			continue
		}
		js.Residue++
	}
	return js
}

// tunedStatus summarises the measured profile.
func tunedStatus(layout paths.Layout, netKey string) *observ.TunedStatus {
	ts := &observ.TunedStatus{Path: layout.TunedFile()}
	t, err := config.LoadTuned(ts.Path)
	if errors.Is(err, os.ErrNotExist) {
		return ts
	}
	if err != nil {
		ts.Err = err.Error()
		return ts
	}
	ts.Present = true
	ts.CreatedAt = t.CreatedAt
	ts.Age = t.Age(time.Now())
	ts.Confidence = t.Confidence
	ts.Strategy = t.Strategy
	ts.SameNetwork = netKey != "" && t.MatchesNetwork(netKey)
	return ts
}

// cacheStatus counts what the verdict store remembers for this network.
func cacheStatus(layout paths.Layout, cfg *config.Loaded, netID policy.NetworkID) observ.CacheStatus {
	cs := observ.CacheStatus{Path: layout.VerdictFile(), Enabled: cfg.Learn}
	if !cfg.Learn {
		return cs
	}
	store, err := policy.OpenStore(cs.Path, time.Now)
	if err != nil {
		cs.Err = err.Error()
		return cs
	}
	defer store.Close()
	store.ForEach(netID, func(_ string, v policy.Verdict) bool {
		cs.Hosts++
		switch v.Source {
		case policy.SrcLearnedPlain:
			cs.Plain++
		case policy.SrcLearnedDesync, policy.SrcProbed:
			cs.Desync++
		default:
			cs.Bypass++
		}
		return true
	})
	return cs
}

// renderStatus writes the human form.
func renderStatus(w io.Writer, st observ.Status, now time.Time) error {
	var b strings.Builder

	if st.Running {
		fmt.Fprintf(&b, "dpb is RUNNING")
		if st.PID > 0 {
			fmt.Fprintf(&b, " (pid %d)", st.PID)
		}
		if !st.Started.IsZero() {
			fmt.Fprintf(&b, ", up %s", now.Sub(st.Started).Round(time.Second))
		}
		b.WriteByte('\n')
	} else {
		b.WriteString("dpb is NOT running\n")
	}
	if st.Version != "" {
		fmt.Fprintf(&b, "version:   %s\n", st.Version)
	}
	if st.Profile != "" {
		fmt.Fprintf(&b, "profile:   %s\n", st.Profile)
	}
	if st.Mode != "" {
		mode := st.Mode
		if st.Suspended {
			mode += " (SUSPENDED: everything relays direct)"
			if st.SuspendReason != "" {
				mode += " — " + st.SuspendReason
			}
		}
		fmt.Fprintf(&b, "mode:      %s\n", mode)
	}
	for _, l := range st.Listeners {
		fmt.Fprintf(&b, "listening: %-7s %s\n", l.Kind, l.Addr)
	}
	for _, a := range st.Applied {
		fmt.Fprintf(&b, "applied:   %s\n", a)
	}
	if len(st.Ladder) > 0 {
		fmt.Fprintf(&b, "ladder:    %s\n", strings.Join(ladderLabels(st.Ladder), " -> "))
	}
	if st.Strategy != "" {
		fmt.Fprintf(&b, "strategy:  %s (forced)\n", st.Strategy)
	}
	if st.NetworkID != "" {
		fmt.Fprintf(&b, "network:   %s\n", st.NetworkID)
	}

	renderResolvers(&b, st.Resolvers)
	renderTuned(&b, st.Tuned)
	renderCache(&b, st.Cache)
	renderJournal(&b, st.Journal)
	renderConns(&b, st.Conns)

	for _, n := range st.Notes {
		fmt.Fprintf(&b, "note:      %s\n", n)
	}

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("status: write: %w", err)
	}
	return nil
}

func renderResolvers(b *strings.Builder, rs []observ.ResolverHealth) {
	if len(rs) == 0 {
		return
	}
	b.WriteString("resolvers:\n")
	for _, r := range rs {
		state := "ok"
		switch {
		case !r.Tried:
			// A rung the chain never reached says nothing about itself. Calling
			// it broken would send a user chasing a resolver that is fine.
			state = "untried"
		case r.Sinkhole:
			state = "POISONED"
		case !r.OK:
			state = "failed"
		}
		line := fmt.Sprintf("  %-28s %-8s", r.Label, state)
		if r.Tried && r.OK {
			line += " " + r.Latency.Round(time.Millisecond).String()
		}
		if r.Err != "" {
			line += "  " + r.Err
		}
		fmt.Fprintln(b, line)
	}
}

func renderTuned(b *strings.Builder, t *observ.TunedStatus) {
	if t == nil {
		return
	}
	switch {
	case t.Err != "":
		fmt.Fprintf(b, "tuned:     unreadable (%s)\n", t.Err)
	case !t.Present:
		fmt.Fprintf(b, "tuned:     none — run `dpb tune` to measure this line\n")
	default:
		line := fmt.Sprintf("tuned:     %s, confidence %s, measured %s ago",
			specLabel(t.Strategy), t.Confidence, t.Age.Round(time.Minute))
		if !t.SameNetwork {
			// A profile measured somewhere else is worse than none: acting on
			// it would desync flows on evidence gathered on another line.
			line += " — ON A DIFFERENT NETWORK, so it is not being used"
		}
		fmt.Fprintln(b, line)
	}
}

func renderCache(b *strings.Builder, c observ.CacheStatus) {
	switch {
	case c.Err != "":
		fmt.Fprintf(b, "cache:     unreadable (%s)\n", c.Err)
	case !c.Enabled:
		fmt.Fprintln(b, "cache:     disabled (learn = false)")
	default:
		fmt.Fprintf(b, "cache:     %d host(s) on this network — %d plain, %d desync\n",
			c.Hosts, c.Plain, c.Desync)
	}
}

func renderJournal(b *strings.Builder, j observ.JournalStatus) {
	switch {
	case j.Err != "":
		fmt.Fprintf(b, "journal:   unreadable (%s)\n", j.Err)
	case j.Pending == 0:
		fmt.Fprintln(b, "journal:   empty — no system change is outstanding")
	case j.Residue > 0:
		fmt.Fprintf(b, "journal:   %d unfinished system change(s) left by a dpb that is gone.\n"+
			"           Run `dpb doctor --repair` to put them back.\n", j.Residue)
	default:
		fmt.Fprintf(b, "journal:   %d change(s) held by the running dpb\n", j.OwnedByLive)
	}
}

func renderConns(b *strings.Builder, s observ.Snapshot) {
	if s.Totals.Conns == 0 {
		return
	}
	fmt.Fprintf(b, "flows:     %d total, %d ok, %d failed; %d judged, %d escalated\n",
		s.Totals.Conns, s.Totals.OK, s.Totals.Failed, s.Totals.Judged, s.Totals.Escalated)
	if s.Hosts > 0 {
		fmt.Fprintf(b, "escalation: %d of %d in-scope host(s) in the last %s\n",
			s.EscalatedHosts, s.Hosts, s.Window)
	}
	if s.Drift != nil {
		fmt.Fprintf(b, "DRIFT:     %s\n           -> %s\n", s.Drift.Suspected, s.Drift.Remedy)
	}
}

func ladderLabels(l []string) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = specLabel(s)
	}
	return out
}

// ── shared plumbing for the M12 commands ────────────────────────────────────

// controlClient builds the client for this layout's control socket.
//
// It goes through Layout.ControlSocket() rather than joining the path here,
// because that accessor falls back to a per-uid name under $TMPDIR when a deep
// home directory would push the socket past darwin's 104-byte sun_path limit.
// The server uses the same accessor, and a client that computed the path itself
// would look in the wrong place on exactly the machines where it matters.
func (g *globals) controlClient(l paths.Layout) *observ.Client {
	return observ.NewClient(l.ControlSocket())
}

// networkIdentity computes the NetworkID the verdict cache is namespaced by.
//
// It is the same computation `dpb run` does, from the same two inputs, because
// a `dpb why` that looked under a different key would report an empty cache on
// a machine whose cache is full.
func (g *globals) networkIdentity(ctx context.Context, cfg *config.Loaded) (policy.NetworkID, error) {
	resolvers, err := buildResolvers(cfg)
	if err != nil {
		return policy.NetworkID{}, err
	}
	env := netstate.Env{Runner: g.runnerOf(), RIB: g.ribOf(), Logf: g.logf}
	facts := g.factsOf(ctx, env)
	if facts == nil {
		// Still return an identity: the resolver-set half is known, and a
		// partial key is a real namespace rather than a failure.
		return networkID(nil, resolvers), errors.New("the machine's network facts could not be collected")
	}
	return networkID(facts, resolvers), nil
}

// sortedKeys is a small helper shared by the report renderers, kept here so the
// three of them format maps the same way.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
