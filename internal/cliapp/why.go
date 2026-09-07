package cliapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/paths"
	"github.com/mumudevx/dpb/internal/policy"
)

// `dpb why HOST` is the command this tool is judged by.
//
// A circumvention tool that silently decides to mangle a bank's TLS handshake
// and gives no account of why is indistinguishable from a bug, and the person
// running it is in a country where they cannot easily ask anyone. So `why`
// answers with the whole chain and its provenance: what the name normalised to,
// every rule that matched and the file it came from, the verdict actually in
// force, where that verdict came from, WHEN it was learned and WHEN it expires,
// and what the last few connections to that host actually did.
//
// It works with no dpb running. That is not a fallback, it is half the point:
// "it worked yesterday" is asked after the process has been stopped and
// started again, and an answer that needs the daemon up cannot be given then.

func newWhyCmd(g *globals) *cobra.Command {
	var (
		port   int
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "why HOST",
		Short: "Explain what dpb decides for a host, and why",
		Long: "why prints the full decision chain for one host: the normalised name, every\n" +
			"scoping rule that matched with the file it came from, the effective verdict\n" +
			"and its source, when a learned verdict was learned and when it expires, and\n" +
			"the most recent connection outcomes.\n\n" +
			"It answers from the running dpb when there is one, so verdicts learned since\n" +
			"start-up are included, and from the configuration and the on-disk verdict\n" +
			"store when there is not.",
		Example: "  dpb why www.isbank.com.tr\n" +
			"  dpb why discord.com --port 443 --json",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWhy(cmd.Context(), g, args[0], port, asJSON)
		},
	}
	cmd.Flags().IntVar(&port, "port", 443, "destination port to decide for")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the decision chain as JSON")
	return cmd
}

// whyReport is the JSON shape and the intermediate the text renderer draws
// from. It carries the explanation plus the facts the explanation itself cannot
// know: which port was asked about, and where the answer came from.
type whyReport struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Live   bool   `json:"live"`
	Source string `json:"answered_from"`
	// Network is the NetworkID the verdict was looked up under. Two different
	// keys are how "it worked yesterday" can be true with an empty cache: the
	// laptop moved, and a verdict learned on one line is deliberately not
	// replayed on another.
	Network string     `json:"network,omitempty"`
	Why     observ.Why `json:"decision"`
	// Mandatory is the compiled-in reason a host is on the hard-veto list. It
	// is the answer to "why does dpb refuse to touch my bank", it is a
	// measurement rather than a preference, and it is quoted verbatim.
	Mandatory string `json:"mandatory_reason,omitempty"`
	// Warnings are things that went wrong while assembling the answer. They are
	// reported rather than swallowed: an unreadable verdict store is exactly
	// the kind of thing that makes "it worked yesterday" true.
	Warnings []string `json:"warnings,omitempty"`
}

func runWhy(ctx context.Context, g *globals, host string, port int, asJSON bool) error {
	if port < 1 || port > 65535 {
		return usagef("why: --port %d is out of range", port)
	}
	rep, err := buildWhy(ctx, g, host, port)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(g.env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fmt.Errorf("why: write JSON: %w", err)
		}
		return nil
	}
	return renderWhy(g.env.Stdout, rep, time.Now())
}

// buildWhy answers from the running dpb if there is one, and from disk if there
// is not.
func buildWhy(ctx context.Context, g *globals, host string, port int) (whyReport, error) {
	rep := whyReport{Host: host, Port: port}
	layout, err := g.layoutOf()
	if err != nil {
		return rep, err
	}

	live, lerr := g.controlClient(layout).Why(ctx, host, port)
	switch {
	case lerr == nil:
		rep.Why = live
		rep.Live = true
		rep.Network = live.Network
		rep.Source = "the running dpb"
		rep.Mandatory = mandatoryReasonFor(live)
		return rep, nil
	case errors.Is(lerr, observ.ErrNotRunning):
		// The ordinary case for a one-shot question. Nothing to report.
	default:
		// The socket is there but the exchange failed. Say so and keep going:
		// a stale answer from disk with a warning beats no answer at all.
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("the running dpb could not answer (%v); this is the on-disk view", lerr))
	}

	why, warnings, err := offlineWhy(ctx, g, layout, host, port)
	rep.Warnings = append(rep.Warnings, warnings...)
	if err != nil {
		return rep, err
	}
	rep.Why = why
	rep.Network = why.Network
	rep.Source = "the configuration and " + layout.VerdictFile()
	rep.Mandatory = mandatoryReasonFor(why)
	return rep, nil
}

// mandatoryReasonFor returns the citation recorded for the compiled-in rule
// that decided, if a compiled-in rule decided.
//
// It looks the reason up by the RULE'S PATTERN rather than by the host, because
// the compiled-in list is a list of patterns: "www.isbank.com.tr" is not in it,
// "isbank.com.tr" is, and asking about the host would silently return nothing
// for every subdomain — which is most of what a user actually types.
func mandatoryReasonFor(w observ.Why) string {
	for _, r := range w.Rules {
		if r.Class != policy.ScopeBypass.String() {
			continue
		}
		if why, ok := config.MandatoryReason(r.Pattern); ok {
			return why
		}
	}
	return ""
}

// offlineWhy assembles the explanation from the same configuration layering
// `dpb run` uses and from the verdict store on disk.
//
// It opens the store only when no dpb is running, which the caller has already
// established. That ordering is deliberate: policy.OpenStore sweeps the
// atomic-write temp files beside the store, and doing that underneath a live
// process mid-flush would delete a file it is about to rename into place.
func offlineWhy(ctx context.Context, g *globals, layout paths.Layout,
	host string, port int) (observ.Why, []string, error) {

	var warnings []string
	cfg, err := scopeConfig(g)
	if err != nil {
		return observ.Why{}, warnings, err
	}
	rules, err := cfg.Rules()
	if err != nil {
		return observ.Why{}, warnings, usagef("%v", err)
	}
	ipRules, err := cfg.IPRules()
	if err != nil {
		return observ.Why{}, warnings, usagef("%v", err)
	}
	matcher, err := policy.NewMatcher(rules)
	if err != nil {
		return observ.Why{}, warnings, usagef("%v", err)
	}
	ipset, err := policy.NewIPSet(ipRules)
	if err != nil {
		return observ.Why{}, warnings, usagef("%v", err)
	}
	ladder, err := cfg.LadderSpecs()
	if err != nil {
		return observ.Why{}, warnings, usagef("%v", err)
	}

	store := policy.NopStore()
	if cfg.Learn {
		s, serr := policy.OpenStore(layout.VerdictFile(), time.Now)
		if serr != nil {
			// A store we cannot read is a real finding, not a reason to refuse
			// to answer: the rules half of the explanation is still true.
			warnings = append(warnings,
				fmt.Sprintf("the verdict store could not be read (%v); learned verdicts are not shown", serr))
		} else {
			store = s
			defer func() {
				if cerr := store.Close(); cerr != nil {
					g.logf("why: close the verdict store: %v", cerr)
				}
			}()
		}
	} else {
		warnings = append(warnings, "learning is disabled in the configuration, so nothing is cached")
	}

	netID, nerr := g.networkIdentity(ctx, cfg)
	if nerr != nil {
		warnings = append(warnings,
			fmt.Sprintf("the network identity could not be collected (%v); "+
				"learned verdicts are namespaced by it, so none will match", nerr))
	}

	engine := policy.NewEngine(policy.EngineOptions{
		Rules:        matcher,
		IPs:          ipset,
		IncludeOnly:  cfg.IncludeOnly(),
		Store:        store,
		NetID:        func() policy.NetworkID { return netID },
		InspectPorts: cfg.InspectPorts,
		Ladder:       ladder,
	})
	return explainWith(engine, host, port, netID, nil), warnings, nil
}

// explainWith assembles the explanation for one host at one port.
//
// It uses Explain for the matched rules and then overrides the verdict with the
// one for the port that was actually asked about. Engine.Explain decides at its
// first inspect port by construction, and quietly answering about 443 when the
// user asked about 8443 would be the wrong answer printed confidently.
func explainWith(engine *policy.Engine, host string, port int,
	netID policy.NetworkID, recent []observ.ConnStat) observ.Why {

	x := engine.Explain(host)
	x.Effective = engine.ForName(host, port)
	w := whyFromExplanation(x, port, netID.Key())
	if recent != nil {
		w.Recent = recent
	}
	return w
}

// whyHandler is what `dpb run` wires into observ.Handler.Why so the live answer
// and the offline answer are assembled by the same function.
//
// It is here rather than in run.go for exactly that reason: two renderings of
// the same decision that are written in two places will disagree eventually,
// and the moment they do, `dpb why` stops being evidence.
func whyHandler(engine *policy.Engine, netID func() policy.NetworkID,
	counters *observ.Counters) func(context.Context, string, int) (observ.Why, error) {

	return func(_ context.Context, host string, port int) (observ.Why, error) {
		if engine == nil {
			return observ.Why{}, errors.New("cliapp: this dpb has no scope engine")
		}
		if port <= 0 {
			ports := engine.InspectPorts()
			if len(ports) > 0 {
				port = ports[0]
			}
		}
		id := policy.NetworkID{}
		if netID != nil {
			id = netID()
		}
		var recent []observ.ConnStat
		if counters != nil {
			recent = counters.Recent(policy.Normalize(host))
			if len(recent) == 0 {
				// An unnamed flow is filed under the address it dialled, and a
				// user who types the address deserves the same history.
				recent = counters.Recent(host)
			}
		}
		return explainWith(engine, host, port, id, recent), nil
	}
}

// whyFromExplanation flattens policy's explanation onto the wire type.
func whyFromExplanation(x policy.Explanation, port int, network string) observ.Why {
	w := observ.Why{
		Host:     x.Input,
		Punycode: x.Punycode,
		Port:     port,
		Network:  network,
		Verdict: observ.WhyVerdict{
			Class:    x.Effective.Class.String(),
			Spec:     x.Effective.Spec,
			Ladder:   append([]string(nil), x.Effective.Ladder...),
			Source:   x.Effective.Source.String(),
			Reason:   x.Effective.Reason,
			RuleText: x.Effective.RuleText,
			RuleFrom: x.Effective.RuleFrom,
			Learned:  x.Effective.Learned,
			Expires:  x.Effective.Expires,
			Wins:     x.Effective.Wins,
			Losses:   x.Effective.Losses,
		},
	}
	for _, r := range x.Matched {
		w.Rules = append(w.Rules, observ.WhyRule{
			Pattern: r.Pattern,
			Class:   r.Class.String(),
			Where:   r.Where(),
		})
	}
	for _, c := range x.Recent {
		w.Recent = append(w.Recent, observ.ConnStat{
			At:       c.At,
			Spec:     c.Spec,
			Attempts: c.Attempts,
			OK:       c.OK,
			Latency:  c.Latency,
		})
	}
	return w
}

// explanationFromWhy is the inverse, so the live answer is rendered by policy's
// own renderer rather than by a second one written here.
func explanationFromWhy(w observ.Why) policy.Explanation {
	x := policy.Explanation{
		Input:    w.Host,
		Punycode: w.Punycode,
		Effective: policy.Verdict{
			Spec:     w.Verdict.Spec,
			Ladder:   append([]string(nil), w.Verdict.Ladder...),
			Reason:   w.Verdict.Reason,
			RuleText: w.Verdict.RuleText,
			RuleFrom: w.Verdict.RuleFrom,
			Learned:  w.Verdict.Learned,
			Expires:  w.Verdict.Expires,
			Wins:     w.Verdict.Wins,
			Losses:   w.Verdict.Losses,
		},
	}
	// An unknown class or source from a newer daemon leaves the zero value,
	// which renders as "bypass"/"builtin-bypass" — the two most conservative
	// readings there are, and never a claim that something is being desynced.
	_ = x.Effective.Class.UnmarshalText([]byte(w.Verdict.Class))
	_ = x.Effective.Source.UnmarshalText([]byte(w.Verdict.Source))

	for _, r := range w.Rules {
		rule := policy.Rule{Pattern: r.Pattern, From: r.Where}
		_ = rule.Class.UnmarshalText([]byte(r.Class))
		x.Matched = append(x.Matched, rule)
	}
	for _, c := range w.Recent {
		x.Recent = append(x.Recent, policy.ConnSummary{
			At:       c.At,
			Spec:     c.Spec,
			Attempts: c.Attempts,
			OK:       c.OK,
			Latency:  c.Latency,
		})
	}
	return x
}

// renderWhy prints the human form: policy's renderer for the decision chain,
// then the facts that belong to the question rather than to the decision.
func renderWhy(w io.Writer, rep whyReport, now time.Time) error {
	x := explanationFromWhy(rep.Why)
	if err := x.TextAt(w, now); err != nil {
		return fmt.Errorf("why: %w", err)
	}
	fmt.Fprintf(w, "port:      %d\n", rep.Port)
	if rep.Network != "" {
		fmt.Fprintf(w, "network:   %s\n", rep.Network)
	}
	if rep.Mandatory != "" {
		fmt.Fprintf(w, "compiled in: %s\n", rep.Mandatory)
	}
	fmt.Fprintf(w, "answered from: %s\n", rep.Source)
	if !rep.Live {
		// Without this line a user cannot tell an empty cache from a daemon
		// that has learned plenty and simply was not asked.
		fmt.Fprintln(w, "  (no dpb is running, so anything learned since the last exit is not shown)")
	}
	for _, note := range rep.Warnings {
		fmt.Fprintf(w, "warning:   %s\n", note)
	}
	return nil
}
