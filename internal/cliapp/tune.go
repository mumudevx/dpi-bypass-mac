package cliapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/buildinfo"
	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/ops"
	"github.com/mumudevx/dpb/internal/paths"
	"github.com/mumudevx/dpb/internal/probe"
	"github.com/mumudevx/dpb/internal/resolve"
)

// The seeded target sets, from the turkey profile. Each one is a measurement,
// not a guess:
//
//   - blocked: MEASUREMENTS.md §1, all three confirmed reset on a benign path.
//     media.discordapp.net (401) and discord.media (520) are deliberately
//     absent — both reach the origin, and shipping them as targets would make
//     the prober chase a block that does not exist.
//   - control: §1 / GT1's trick — the same address with a benign SNI, which is
//     what isolates the hostname from every routing variable.
//   - fragile: §5's ten regressors, every one a Turkish bank or .gov.tr.
var (
	seedBlocked = []string{"discord.com", "discord.gg", "cdn.discordapp.com"}
	seedControl = []string{"cloudflare.com"}
	seedFragile = []string{
		"www.akbank.com",
		"www.isbank.com.tr",
		"www.yapikredi.com.tr",
		"www.ziraatbank.com.tr",
		"www.vakifbank.com.tr",
		"www.denizbank.com",
		"www.turkiye.gov.tr",
		"www.gib.gov.tr",
		"www.mhrs.gov.tr",
		"www.btk.gov.tr",
	}
)

type tuneFlags struct {
	control     []string
	fragile     []string
	reps        int
	depth       string
	concurrency int
	cooldown    time.Duration
	budget      time.Duration
	timeout     time.Duration
	seed        int64
	noClassify  bool
	write       bool
	out         string
	asJSON      bool
	export      bool
	dnsOnly     bool
	insecure    bool
	caFile      string
	network     string
}

func newTuneCmd(g *globals) *cobra.Command {
	var f tuneFlags

	cmd := &cobra.Command{
		Use:   "tune [target ...]",
		Short: "Measure this line and write a profile",
		Long: "tune measures YOUR line with the emitters this build actually ships, and writes\n" +
			"what it found.\n\n" +
			"It runs six phases: the DNS transport matrix, a baseline that establishes which\n" +
			"targets are really blocked here, mechanism classification, the discrete candidate\n" +
			"sweep, ranking on two axes, and the write-back.\n\n" +
			"Both axes matter. MEASUREMENTS.md §5.1 measured every bypassing emitter breaking\n" +
			"Turkish online banking, so a strategy that fixes one site and breaks another is\n" +
			"worse than useless. Every candidate is therefore scored against blocked hosts,\n" +
			"fragile hosts and ordinary controls at once.\n\n" +
			"It mutates no system state and needs no root. The only thing it writes is the\n" +
			"tuned profile, and deleting that file undoes it completely.\n\n" +
			"Exit codes, for scripts: 0 a profile was measured; exit 6 nothing in the target\n" +
			"set is blocked on this line, so there is nothing to measure and nothing was\n" +
			"written; exit 5 the block is at the IP layer, which no packet strategy can\n" +
			"defeat; exit 1 the measurement itself failed. tune never needs root, so it\n" +
			"never returns 4 — that code belongs to `dpb service install --system`.",
		Example: "  dpb tune\n" +
			"  dpb tune discord.com@162.159.128.233 --reps 5 --depth paranoid\n" +
			"  dpb tune --dns-only\n" +
			"  dpb tune --json --no-write",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTune(cmd.Context(), g, f, args)
		},
	}

	fl := cmd.Flags()
	fl.StringSliceVar(&f.control, "control", seedControl,
		"benign-SNI control hosts, pinned to each target's own address")
	fl.StringSliceVar(&f.fragile, "fragile", seedFragile,
		"hosts known to break under aggressive emitters; scored, never disqualifying")
	fl.IntVar(&f.reps, "reps", 0, "attempts per candidate per target (default: from --depth)")
	fl.StringVar(&f.depth, "depth", probe.DepthFull, "sweep depth: quick, full or paranoid")
	fl.IntVar(&f.concurrency, "concurrency", probe.DefaultConcurrency, "trials in flight at once")
	fl.DurationVar(&f.cooldown, "cooldown", probe.DefaultCooldown, "pause between rounds")
	fl.DurationVar(&f.budget, "budget", probe.DefaultBudget, "wall-clock budget for the sweep")
	fl.DurationVar(&f.timeout, "timeout", probe.DefaultTrialTimeout, "budget for one attempt")
	fl.Int64Var(&f.seed, "seed", 0, "shuffle seed; 0 is a fixed constant, never the clock")
	fl.BoolVar(&f.noClassify, "no-classify", false, "skip mechanism classification")
	fl.BoolVar(&f.write, "write", true, "write the tuned profile (--write=false to measure only)")
	fl.StringVar(&f.out, "out", "", "path to write instead of the default profile location")
	fl.BoolVar(&f.asJSON, "json", false, "emit the whole session as JSON")
	fl.BoolVar(&f.export, "export", false, "print one pasteable line others can verify locally")
	fl.BoolVar(&f.dnsOnly, "dns-only", false, "run the DNS transport matrix and stop")
	fl.StringVar(&f.network, "network-key", "",
		"namespace the profile under this network identity instead of an unnamed one")
	fl.BoolVar(&f.insecure, "insecure", false,
		"skip certificate verification; PASS then no longer proves the origin was reached")
	fl.StringVar(&f.caFile, "ca-file", "", "PEM roots to verify against instead of the system store")

	return cmd
}

func runTune(ctx context.Context, g *globals, f tuneFlags, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f.insecure && f.caFile != "" {
		return usagef("tune: --insecure and --ca-file contradict each other")
	}
	switch strings.ToLower(f.depth) {
	case probe.DepthQuick, probe.DepthFull, probe.DepthParanoid:
	default:
		return usagef("tune: --depth %q; want quick, full or paranoid", f.depth)
	}

	targets, err := tuneTargets(args, f)
	if err != nil {
		return err
	}

	reg := ops.Install()
	rs, err := resolve.DefaultResolvers(nil, nil)
	if err != nil {
		return fmt.Errorf("tune: build resolver chain: %w", err)
	}
	chain := resolve.NewChain(resolve.Options{Resolvers: rs, Logf: g.logf})

	o := probe.Options{
		Targets:     targets,
		Reps:        f.reps,
		Concurrency: f.concurrency,
		Cooldown:    f.cooldown,
		Budget:      f.budget,
		Timeout:     f.timeout,
		Depth:       f.depth,
		Registry:    reg,
		Chain:       chain,
		Resolvers:   rs,
		Dial:        &flow.NetDialer{Resolve: chain.Resolve, Logf: g.logf},
		// No governor. A coalesced plan is not the plan that was asked for, and
		// a prober that scores a strategy it did not emit is worse than useless.
		Sender: &emit.Sender{Logf: g.logf},
		Seed:   f.seed,
		Logf:   g.logf,
	}
	switch {
	case f.insecure:
		o.TLSConfig = insecureConfig
	case f.caFile != "":
		cfg, err := caConfig(f.caFile)
		if err != nil {
			return err
		}
		o.TLSConfig = cfg
	}
	if !f.asJSON {
		o.OnProgress = tuneProgress(g)
	}

	r := probe.NewRunner(o)
	if f.dnsOnly {
		return runDNSOnly(ctx, g, r)
	}

	rep, runErr := r.Run(ctx)
	rep.ToolVersion = buildinfo.Short()
	rep.NetworkKey = f.network
	if f.noClassify {
		// The classification still ran — it is what orders the sweep — but the
		// operator asked not to be told, so the mechanism section is dropped
		// from the report rather than quietly kept.
		rep.Class.Evidence = nil
	}

	if err := emitReport(g, rep, f); err != nil {
		return err
	}

	written, werr := maybeWrite(g, rep, f, runErr)
	if werr != nil {
		return werr
	}
	if written == "" && runErr == nil && f.write {
		fmt.Fprintf(g.env.Stderr, "dpb: nothing was written: there is no measured result to record\n")
	}
	return tuneExit(rep, runErr)
}

// tuneExit maps the run's outcome onto an exit code and a sentence.
func tuneExit(rep probe.Report, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, probe.ErrIPBlock):
		return refusedError{fmt.Errorf(
			"the destination is unreachable even with a benign SNI, so no packet strategy can "+
				"help here. This is an address-level block, not the SNI-keyed one dpb defeats "+
				"(MEASUREMENTS.md §1). Blocked at the IP layer: %s",
			strings.Join(rep.Blocked, ", "))}
	case errors.Is(err, probe.ErrNothingBlocked):
		return codedError{code: ExitNothingBlocked, err: errors.New(
			"nothing in the target set is blocked on this network, so there is no strategy to " +
				"find and none was invented. Run `dpb tune <host>` with a host you know is " +
				"blocked, or use dpb as-is: default-direct costs nothing when nothing is blocked")}
	case errors.Is(err, resolve.ErrNoCleanTransport):
		return fmt.Errorf("%w\n\nNo packet strategy fixes a poisoned resolver. Fix DNS first: "+
			"`dpb dns check` shows which transports were tried", err)
	default:
		return err
	}
}

func maybeWrite(g *globals, rep probe.Report, f tuneFlags, runErr error) (string, error) {
	if !f.write || runErr != nil {
		return "", nil
	}
	path := f.out
	if path == "" {
		l, err := paths.Resolve()
		if err != nil {
			return "", fmt.Errorf("tune: locate the profile directory: %w", err)
		}
		if err := l.EnsureDirs(); err != nil {
			return "", fmt.Errorf("tune: create the profile directory: %w", err)
		}
		path = l.TunedFile()
		defer func() { _ = l.Chown(path) }()
	}
	if err := rep.WriteConfig(path); err != nil {
		return "", err
	}
	// The notice follows the report on stdout for a human, and goes to stderr
	// whenever stdout is a machine format: `dpb tune --json | jq` must not have
	// to strip a sentence off the end of the document.
	w := g.env.Stdout
	if f.asJSON || f.export {
		w = g.env.Stderr
	}
	fmt.Fprintf(w, "\nwrote %s (confidence %s)\n", path, rep.Confidence)
	fmt.Fprintf(w, "delete that file to go back to the shipped profile.\n")
	return path, nil
}

func emitReport(g *globals, rep probe.Report, f tuneFlags) error {
	switch {
	case f.asJSON:
		return rep.JSON(g.env.Stdout)
	case f.export:
		fmt.Fprintln(g.env.Stdout, rep.Export())
		return nil
	default:
		return rep.Text(g.env.Stdout)
	}
}

func runDNSOnly(ctx context.Context, g *globals, r *probe.Runner) error {
	_, err := r.Preflight(ctx)
	writeDNSMatrix(g.env.Stdout, r.Matrix())
	for _, w := range r.Warnings() {
		fmt.Fprintf(g.env.Stderr, "dpb: %s\n", w)
	}
	if err != nil {
		return fmt.Errorf("%w\n\nNo packet strategy fixes a poisoned resolver", err)
	}
	return nil
}

// tuneProgress prints a single rewritten status line to stderr. It goes to
// stderr so that `dpb tune > report.txt` keeps the report clean.
func tuneProgress(g *globals) func(probe.Progress) {
	last := time.Time{}
	return func(p probe.Progress) {
		now := time.Now()
		if p.Done < p.Total && now.Sub(last) < 250*time.Millisecond {
			return
		}
		last = now
		if p.Total == 0 {
			fmt.Fprintf(g.env.Stderr, "\r%-70s", "phase: "+p.Phase)
			return
		}
		fmt.Fprintf(g.env.Stderr, "\r%-70s",
			fmt.Sprintf("%s  %d/%d trials  %s elapsed  ~%s left",
				p.Phase, p.Done, p.Total, p.Elapsed.Round(time.Second), p.ETA.Round(time.Second)))
	}
}

// tuneTargets turns the command line into the target set.
//
// Every target is pinned where an address was given. A target with no address
// is resolved through dpb's own chain at baseline time and pinned then, never
// left to a hostname dial: MEASUREMENTS.md §5.4 records a whole compatibility
// matrix invalidated because Go's resolver answered blocked names with the ISP
// sinkhole and every emitter was scored against a blackhole.
func tuneTargets(args []string, f tuneFlags) ([]probe.Target, error) {
	blocked := args
	if len(blocked) == 0 {
		blocked = seedBlocked
	}
	out := make([]probe.Target, 0, len(blocked)+len(f.control)+len(f.fragile))
	for _, group := range []struct {
		hosts []string
		kind  probe.TargetKind
	}{
		{blocked, probe.TargetBlocked},
		{f.control, probe.TargetControl},
		{f.fragile, probe.TargetFragile},
	} {
		for _, spec := range group.hosts {
			if strings.TrimSpace(spec) == "" {
				// An empty entry is how a flag says "none of these": `--fragile ""`
				// drops the fragile axis for a run that only wants a bypass answer.
				continue
			}
			t, err := parseTargetSpec(spec, group.kind)
			if err != nil {
				return nil, err
			}
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, usagef("tune: no targets")
	}
	return out, nil
}

// parseTargetSpec accepts HOST, HOST:PORT, HOST@ADDR and HOST:PORT@ADDR.
func parseTargetSpec(spec string, kind probe.TargetKind) (probe.Target, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return probe.Target{}, usagef("tune: empty target")
	}
	t := probe.Target{Kind: kind}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		addr := s[i+1:]
		s = s[:i]
		// An address may carry a port, which is how a test aims a target at a
		// loopback listener on an ephemeral port.
		if h, p, err := net.SplitHostPort(addr); err == nil {
			addr = h
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return probe.Target{}, usagef("tune: %q: %q is not a port", spec, p)
			}
			t.Port = n
		}
		if _, err := netip.ParseAddr(addr); err != nil {
			return probe.Target{}, usagef("tune: %q: %q is not an IP address", spec, addr)
		}
		t.Addr = addr
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		s = h
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return probe.Target{}, usagef("tune: %q: %q is not a port", spec, p)
		}
		t.Port = n
	}
	t.Host = s
	if err := t.Validate(); err != nil {
		return probe.Target{}, usagef("%v", err)
	}
	return t, nil
}
