package cliapp

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

type applyFlags struct {
	targets  []string
	reps     int
	cooldown time.Duration
	timeout  time.Duration
	control  []string
	fragile  []string
	out      string
	write    bool
	force    bool
	network  string
	insecure bool
	caFile   string
}

func newApplyCmd(g *globals) *cobra.Command {
	var f applyFlags

	cmd := &cobra.Command{
		Use:   "apply SPEC",
		Short: "Import a shared strategy, re-verify it here, then write it",
		Long: "apply takes a strategy someone posted in a forum or a Telegram group and does the\n" +
			"one thing that makes sharing safe: it MEASURES it on your line before writing it.\n\n" +
			"MEASUREMENTS.md §3.5 is blunt about why. The dossier's chunk curve, measured\n" +
			"through SpoofDPI, does not reproduce through this tool's own emitters — \"strategy\n" +
			"parameters are not portable between implementations\". A spec that works for the\n" +
			"person who posted it may do nothing here, and §5.1 shows the failure is not\n" +
			"symmetric: an emitter that does nothing for you can still break your bank.\n\n" +
			"So the spec is parsed, then run against blocked, fragile and control targets, and\n" +
			"written only if it actually bypassed something without breaking the controls.",
		Example: "  dpb apply 'tlsfrag:pos=snimid'\n" +
			"  dpb apply 'chunk:size=12' --reps 5\n" +
			"  dpb apply 'oob:pos=1' --write=false      # measure it, write nothing",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(cmd.Context(), g, f, args[0])
		},
	}

	fl := cmd.Flags()
	fl.StringSliceVar(&f.targets, "target", seedBlocked,
		"blocked hosts to verify against, as HOST[:PORT][@ADDR]")
	fl.IntVar(&f.reps, "reps", 3, "attempts per target")
	fl.DurationVar(&f.cooldown, "cooldown", probe.DefaultCooldown, "pause between rounds")
	fl.DurationVar(&f.timeout, "timeout", probe.DefaultTrialTimeout, "budget for one attempt")
	fl.StringSliceVar(&f.control, "control", seedControl, "benign-SNI control hosts")
	fl.StringSliceVar(&f.fragile, "fragile", seedFragile, "hosts known to break under aggressive emitters")
	fl.StringVar(&f.out, "out", "", "path to write instead of the default profile location")
	fl.BoolVar(&f.write, "write", true, "write the profile when the strategy verifies")
	fl.BoolVar(&f.force, "force", false,
		"write even when the strategy did not verify here; the profile is marked low confidence")
	fl.StringVar(&f.network, "network-key", "", "namespace the profile under this network identity")
	fl.BoolVar(&f.insecure, "insecure", false, "skip certificate verification")
	fl.StringVar(&f.caFile, "ca-file", "", "PEM roots to verify against instead of the system store")

	return cmd
}

func runApply(ctx context.Context, g *globals, f applyFlags, spec string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f.insecure && f.caFile != "" {
		return usagef("apply: --insecure and --ca-file contradict each other")
	}

	reg := ops.Install()
	strat, err := reg.Get(spec)
	if err != nil {
		// A rejected op reaches here with a cited reason rather than "unknown
		// op", which is the difference between sending someone to fix a typo
		// and telling them the mechanism cannot work.
		return usagef("%v", err)
	}
	if strat.IsPlain() {
		return usagef("apply: %q is the plain strategy, which is already rung 1 of every ladder; "+
			"there is nothing to import", spec)
	}
	fmt.Fprintf(g.env.Stdout, "verifying %s on this line before writing it\n\n", strat.Label())
	for _, line := range strat.Explain() {
		fmt.Fprintf(g.env.Stdout, "  %s\n", line)
	}
	fmt.Fprintln(g.env.Stdout)

	targets, err := tuneTargets(f.targets, tuneFlags{control: f.control, fragile: f.fragile})
	if err != nil {
		return err
	}

	rs, err := resolve.DefaultResolvers(nil, nil)
	if err != nil {
		return fmt.Errorf("apply: build resolver chain: %w", err)
	}
	chain := resolve.NewChain(resolve.Options{Resolvers: rs, Logf: g.logf})

	o := probe.Options{
		Targets:   targets,
		Reps:      f.reps,
		Cooldown:  f.cooldown,
		Timeout:   f.timeout,
		Registry:  reg,
		Chain:     chain,
		Resolvers: rs,
		Dial:      &flow.NetDialer{Resolve: chain.Resolve, Logf: g.logf},
		Sender:    &emit.Sender{Logf: g.logf},
		Logf:      g.logf,
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

	rep, err := verifyOne(ctx, o, strat)
	rep.ToolVersion = buildinfo.Short()
	rep.NetworkKey = f.network
	if terr := rep.Text(g.env.Stdout); terr != nil {
		return terr
	}
	if err != nil {
		return tuneExit(rep, err)
	}

	best, ok := rep.Winner()
	verified := ok && best.Spec == strat.Spec
	switch {
	case verified:
		fmt.Fprintf(g.env.Stdout, "\n%s VERIFIED here: %d/%d bypass, %d/%d controls still working.\n",
			strat.Label(), best.BypassPass, best.BypassTotal, best.ControlPass, best.ControlTotal)
	case !f.force:
		return fmt.Errorf("%s did not bypass anything on this line, so it was NOT written. "+
			"MEASUREMENTS.md §3.5: strategy parameters are not portable between implementations "+
			"or between lines. Run `dpb tune` to measure yours, or pass --force to write it anyway",
			strat.Label())
	default:
		fmt.Fprintf(g.env.Stderr,
			"dpb: %s did not verify here; writing it anyway because --force was given\n", strat.Label())
	}

	if !f.write {
		return nil
	}
	return writeApplied(g, rep, strat, f, verified)
}

// verifyOne runs the phases an imported strategy needs: the baseline that says
// which targets are really blocked, then that one candidate against all of them.
//
// It deliberately does NOT run the classifier or the sweep. The operator named
// the strategy; the question is whether it works here, not which one is best.
func verifyOne(ctx context.Context, o probe.Options, s strategy.Strategy) (probe.Report, error) {
	r := probe.NewRunner(o)

	if _, err := r.Preflight(ctx); err != nil {
		return probe.Report{Confidence: probe.ConfidenceLow, Warnings: r.Warnings()}, err
	}
	blocked, notBlocked, err := r.Baseline(ctx)
	rep := probe.Report{
		CreatedAt:  time.Now(),
		Blocked:    targetHosts(blocked),
		NotBlocked: targetHosts(notBlocked),
		DNS:        nil,
		Matrix:     r.Matrix(),
		Confidence: probe.ConfidenceLow,
	}
	if err != nil {
		rep.Warnings = r.Warnings()
		return rep, err
	}
	if len(blocked) == 0 {
		rep.Warnings = r.Warnings()
		return rep, probe.ErrNothingBlocked
	}

	plain, err := o.Registry.Get("")
	if err != nil {
		return rep, err
	}
	trials, err := r.Evaluate(ctx, []strategy.Strategy{plain, s})
	rep.Trials = trials
	rep.Ranked = probe.Rank(trials, blocked, o.Registry.Docs())
	rep.Warnings = r.Warnings()
	rep.Ladder = []string{"", s.Spec}
	if best, ok := rep.Winner(); ok {
		rep.Confidence = probe.Confidence(best, len(blocked), o.Reps, rep.NoiseRate)
	}
	return rep, err
}

func targetHosts(ts []probe.Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.String())
	}
	return out
}

func writeApplied(g *globals, rep probe.Report, s strategy.Strategy, f applyFlags, verified bool) error {
	tuned := rep.Tuned()
	tuned.Strategy = s.Spec
	tuned.Ladder = []string{"", s.Spec}
	if !verified {
		// An unverified import must never claim a confidence it did not earn.
		tuned.Confidence = config.ConfidenceLow
		tuned.Warnings = append(tuned.Warnings,
			"this strategy was imported with --force and did NOT bypass anything when measured here")
	}

	path := f.out
	if path == "" {
		l, err := paths.Resolve()
		if err != nil {
			return fmt.Errorf("apply: locate the profile directory: %w", err)
		}
		if err := l.EnsureDirs(); err != nil {
			return fmt.Errorf("apply: create the profile directory: %w", err)
		}
		path = l.TunedFile()
		defer func() { _ = l.Chown(path) }()
	}
	if err := tuned.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(g.env.Stdout, "wrote %s (confidence %s)\n", path, tuned.Confidence)
	fmt.Fprintf(g.env.Stdout, "delete that file to go back to the shipped profile.\n")
	return nil
}
