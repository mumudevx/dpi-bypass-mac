package cliapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
)

// probeCooldown separates reps. MEASUREMENTS.md §6 shows the DPI carries no
// state between flows — 15 back-to-back blocked attempts did not change the
// outcome of the 16th — so this is not there to dodge escalation. It is there
// so five reps are five independent samples of the network rather than one
// burst that shares a queue.
const probeCooldown = 200 * time.Millisecond

type probeFlags struct {
	host     string
	addr     string
	spec     string
	reps     int
	port     int
	timeout  time.Duration
	asJSON   bool
	insecure bool
	caFile   string
}

func newProbeCmd(g *globals) *cobra.Command {
	var f probeFlags

	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Dial one host with one strategy and report a verdict",
		Long: "probe is the measurement instrument and the smallest runnable slice of dpb.\n\n" +
			"It dials a host through the same dialler, the same strategy compiler and the\n" +
			"same emitter the proxy uses, completes a real TLS handshake and validates the\n" +
			"certificate against the name. PASS means exactly that; it never means \"the TCP\n" +
			"connection opened\".\n\n" +
			"Pin the destination with --addr. MEASUREMENTS.md §5.4 records a whole\n" +
			"compatibility matrix invalidated because the system resolver answered blocked\n" +
			"names with the ISP sinkhole, so every emitter was scored against a blackhole.\n\n" +
			"It mutates nothing, needs no root, and needs neither the proxy nor the tunnel.",
		Example: "  dpb probe --host discord.com --addr 162.159.128.233\n" +
			"  dpb probe --host discord.com --addr 162.159.128.233 --strategy tlsfrag:pos=snimid\n" +
			"  dpb probe --host cloudflare.com --addr 162.159.128.233   # same IP, benign SNI",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProbe(cmd.Context(), g, f)
		},
	}

	fl := cmd.Flags()
	fl.StringVar(&f.host, "host", "", "hostname to probe (sent as the TLS SNI); required")
	fl.StringVar(&f.addr, "addr", "", "pin the destination IP and skip resolution")
	fl.StringVar(&f.spec, "strategy", "", `strategy spec, e.g. "tlsfrag:pos=snimid"; empty means plain`)
	fl.IntVar(&f.reps, "reps", 5, "attempts to make")
	fl.IntVar(&f.port, "port", probe.DefaultPort, "destination port")
	fl.DurationVar(&f.timeout, "timeout", probe.DefaultTrialTimeout, "budget for one attempt")
	fl.BoolVar(&f.asJSON, "json", false, "emit the result as JSON")
	fl.BoolVar(&f.insecure, "insecure", false,
		"skip certificate verification; PASS then no longer proves the origin was reached")
	fl.StringVar(&f.caFile, "ca-file", "",
		"PEM roots to verify against instead of the system store")

	return cmd
}

func runProbe(ctx context.Context, g *globals, f probeFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f.host == "" {
		return usagef("probe: --host is required")
	}
	if f.reps < 1 {
		return usagef("probe: --reps must be at least 1, got %d", f.reps)
	}

	// Installing the op set is what makes a spec parseable. A blank import is
	// deliberately not enough (see ops.Install).
	reg := ops.Install()
	strat, err := reg.Get(f.spec)
	if err != nil {
		return usagef("%v", err)
	}

	target := probe.Target{Host: f.host, Port: f.port, Kind: probe.TargetBlocked, Addr: f.addr}
	if err := target.Validate(); err != nil {
		return usagef("%v", err)
	}

	dial := &flow.NetDialer{Logf: g.logf}
	if f.addr == "" {
		chain, err := probeChain(g)
		if err != nil {
			return err
		}
		dial.Resolve = chain.Resolve
	}

	opts := probe.TrialOptions{
		Dial: dial,
		// No governor: a coalesced plan is not the plan that was asked for, and
		// a prober that scores a strategy it did not emit is worse than useless.
		Sender:  &emit.Sender{Logf: g.logf},
		Timeout: f.timeout,
		Logf:    g.logf,
	}
	switch {
	case f.insecure && f.caFile != "":
		return usagef("probe: --insecure and --ca-file contradict each other")
	case f.insecure:
		opts.TLSConfig = insecureConfig
	case f.caFile != "":
		cfg, err := caConfig(f.caFile)
		if err != nil {
			return err
		}
		opts.TLSConfig = cfg
	}

	res := probeResult{
		Host:     target.Host,
		Addr:     target.Addr,
		Port:     target.DialPort(),
		Strategy: strat.Spec,
		Label:    strat.Label(),
		Reps:     f.reps,
	}

	for i := 0; i < f.reps; i++ {
		if i > 0 {
			if err := sleepCtx(ctx, probeCooldown); err != nil {
				res.Aborted = true
				break
			}
		}
		tr := probe.RunTrial(ctx, strat, target, i+1, opts)
		res.Trials = append(res.Trials, tr)
		if tr.Verdict == probe.VerdictPass {
			res.Pass++
		}
		if res.Peer == "" && tr.Peer.IsValid() {
			res.Peer = tr.Peer.Addr().String()
		}
	}

	res.Verdict = summarise(res.Trials)

	if f.asJSON {
		if err := res.writeJSON(g.env.Stdout); err != nil {
			return err
		}
	} else {
		res.writeText(g.env.Stdout)
	}

	if res.Aborted {
		return ctx.Err()
	}
	if res.Pass == len(res.Trials) && res.Pass > 0 {
		return nil
	}
	// A non-PASS is a successful measurement, not a broken command, but the
	// exit code has to say "this host is not reachable this way" so a script or
	// a bisect loop can branch on it.
	return fmt.Errorf("%s: %d/%d PASS with strategy %s (verdict %s)",
		target, res.Pass, len(res.Trials), strat.Label(), res.Verdict)
}

// probeChain builds the shipped resolver chain. It exists for the case where no
// --addr was given; the pinned path never touches it.
func probeChain(g *globals) (*resolve.Chain, error) {
	rs, err := resolve.DefaultResolvers(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("probe: build resolver chain: %w", err)
	}
	return resolve.NewChain(resolve.Options{Resolvers: rs, Logf: g.logf}), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type probeResult struct {
	Host     string
	Addr     string
	Peer     string
	Port     int
	Strategy string
	Label    string
	Reps     int
	Pass     int
	Verdict  probe.Verdict
	Aborted  bool
	Trials   []probe.Trial
}

// summarise picks the headline verdict: PASS when every rep passed, otherwise
// the most frequent failure. Ties break toward the more severe verdict so a
// 2 RESET / 2 TIMEOUT split never reports the gentler one and never flips
// between runs.
func summarise(ts []probe.Trial) probe.Verdict {
	if len(ts) == 0 {
		return probe.VerdictUnknown
	}
	counts := map[probe.Verdict]int{}
	all := true
	for _, t := range ts {
		counts[t.Verdict]++
		if t.Verdict != probe.VerdictPass {
			all = false
		}
	}
	if all {
		return probe.VerdictPass
	}
	delete(counts, probe.VerdictPass)
	worst := probe.VerdictUnknown
	for v, n := range counts {
		switch {
		case worst == probe.VerdictUnknown, n > counts[worst], n == counts[worst] && v > worst:
			worst = v
		}
	}
	return worst
}

func (r probeResult) writeText(w io.Writer) {
	where := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	if r.Addr != "" {
		where += " [" + r.Addr + "]"
	} else if r.Peer != "" {
		where += " [" + r.Peer + "]"
	}
	fmt.Fprintf(w, "probe %s  strategy %s\n\n", where, r.Label)

	for _, t := range r.Trials {
		fmt.Fprintf(w, "  rep %d  %-14s %7s", t.Round, t.Verdict, roundMillis(t.Latency))
		if t.Segments > 0 {
			fmt.Fprintf(w, "  %d seg", t.Segments)
		}
		if t.Err != "" {
			fmt.Fprintf(w, "  %s", oneLine(t.Err))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "\n%d/%d PASS   verdict %s\n", r.Pass, len(r.Trials), r.Verdict)
	if note := remedy(r); note != "" {
		fmt.Fprintf(w, "%s\n", note)
	}
}

// remedy turns a verdict into the next thing to try. A measurement instrument
// that leaves the user holding a label and no action has done half a job.
func remedy(r probeResult) string {
	switch r.Verdict {
	case probe.VerdictPass:
		return ""
	case probe.VerdictReset, probe.VerdictTimeout:
		if r.Strategy == "" {
			return "This host is reset with no desync. Try --strategy tlsfrag:pos=snimid,\n" +
				"the rule-based emitter from MEASUREMENTS.md §3.2."
		}
		return "This strategy does not clear the block here. Try another rung:\n" +
			"  dpb strategy list --ladder tr"
	case probe.VerdictBlockPage:
		return "The connection reached a censor, not the origin. Pin the real address with\n" +
			"--addr; the system resolver answers blocked names with the ISP sinkhole\n" +
			"(MEASUREMENTS.md §2, §5.4)."
	case probe.VerdictHandshakeFail:
		return "The origin refused the handshake. That is a compatibility failure of the\n" +
			"strategy against this server, not a DPI result (MEASUREMENTS.md §5)."
	case probe.VerdictDialFail:
		return "The TCP connection never opened, so no desync can help. Check the address\n" +
			"and whether the path is up."
	case probe.VerdictLocalError:
		return "dpb could not emit the strategy it was asked for, so nothing was measured."
	default:
		return ""
	}
}

// probeJSON is the machine-readable form. It is a separate type rather than
// tags on probeResult because the wire shape of a report is a contract with
// whoever parses it, and it must not drift every time an internal field moves.
type probeJSON struct {
	Host     string      `json:"host"`
	Addr     string      `json:"addr,omitempty"`
	Peer     string      `json:"peer,omitempty"`
	Port     int         `json:"port"`
	Strategy string      `json:"strategy"`
	Label    string      `json:"label"`
	Reps     int         `json:"reps"`
	Pass     int         `json:"pass"`
	Total    int         `json:"total"`
	Verdict  string      `json:"verdict"`
	Aborted  bool        `json:"aborted,omitempty"`
	Trials   []trialJSON `json:"trials"`
}

type trialJSON struct {
	Round     int    `json:"round"`
	Verdict   string `json:"verdict"`
	LatencyMs int64  `json:"latency_ms"`
	Segments  int    `json:"segments,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Err       string `json:"error,omitempty"`
	At        string `json:"at"`
}

func (r probeResult) json() probeJSON {
	o := probeJSON{
		Host: r.Host, Addr: r.Addr, Peer: r.Peer, Port: r.Port,
		Strategy: r.Strategy, Label: r.Label, Reps: r.Reps,
		Pass: r.Pass, Total: len(r.Trials),
		Verdict: r.Verdict.String(), Aborted: r.Aborted,
		Trials: make([]trialJSON, 0, len(r.Trials)),
	}
	for _, t := range r.Trials {
		tj := trialJSON{
			Round:     t.Round,
			Verdict:   t.Verdict.String(),
			LatencyMs: t.Latency.Milliseconds(),
			Segments:  t.Segments,
			Err:       t.Err,
			At:        t.At.UTC().Format(time.RFC3339Nano),
		}
		if t.Peer.IsValid() {
			tj.Peer = t.Peer.String()
		}
		o.Trials = append(o.Trials, tj)
	}
	return o
}

func (r probeResult) writeJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r.json()); err != nil {
		return fmt.Errorf("probe: write JSON: %w", err)
	}
	return nil
}

// caConfig verifies against an explicit PEM bundle instead of the system trust
// store. It keeps PASS meaning "the certificate validates for the name" when
// the origin is one whose issuer the machine does not know — a test fixture, or
// a network whose roots are pinned by hand.
func caConfig(path string) (func(string) *tls.Config, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("probe: read --ca-file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("probe: --ca-file %s holds no PEM certificate", path)
	}
	return func(host string) *tls.Config {
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: pool}
	}, nil
}

// insecureConfig is what --insecure buys: a handshake that proves the path
// carries TLS records, and nothing about who answered. It exists for probing an
// origin whose certificate we do not trust — a test fixture, a captive box —
// and the report says so, because otherwise PASS would quietly change meaning.
func insecureConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}

func roundMillis(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(time.Millisecond).String()
}
