package cliapp

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
)

func newDNSCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Inspect the resolver chain",
		Long: "dns shows what dpb's own resolver chain does on this network.\n\n" +
			"It matters more here than on most networks. MEASUREMENTS.md §2 measured\n" +
			"per-QNAME drops on :53 for every public resolver, connection resets on TCP/53 at\n" +
			"every port, and the ISP resolver answering every blocked name with the BTK\n" +
			"sinkhole 195.175.254.2 — while alternate-port UDP answered truthfully. No packet\n" +
			"strategy fixes a poisoned resolver, so this is the first thing to check.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetOut(g.env.Stderr)
			_ = cmd.Help()
			return usagef("dns: no subcommand given")
		},
	}
	cmd.AddCommand(newDNSCheckCmd(g), newDNSResolveCmd(g))
	return cmd
}

func newDNSCheckCmd(g *globals) *cobra.Command {
	var names []string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Measure every DNS transport against a control and the blocked names",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDNSCheck(cmd.Context(), g, names)
		},
	}
	cmd.Flags().StringSliceVar(&names, "name", seedBlocked,
		"names to test each transport against, besides the control")
	return cmd
}

func runDNSCheck(ctx context.Context, g *globals, names []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rs, err := resolve.DefaultResolvers(nil, nil)
	if err != nil {
		return fmt.Errorf("dns check: build resolver chain: %w", err)
	}
	targets := make([]probe.Target, 0, len(names))
	for _, n := range names {
		t, err := parseTargetSpec(n, probe.TargetBlocked)
		if err != nil {
			return err
		}
		targets = append(targets, t)
	}

	r := probe.NewRunner(probe.Options{Targets: targets, Resolvers: rs, Logf: g.logf})
	health, perr := r.Preflight(ctx)
	writeDNSMatrix(g.env.Stdout, r.Matrix())
	writeDNSHealth(g.env.Stdout, health)
	if perr != nil {
		return fmt.Errorf("%w\n\nNo packet strategy fixes a poisoned resolver: every transport "+
			"above is either dropped or answering with a censor's address", perr)
	}
	return nil
}

// writeDNSMatrix renders the phase-1 table.
//
// A cell reads "-" when the transport was never asked, "ok" for a genuine
// answer, and SINKHOLE for the measured censorship signal. The three are
// deliberately distinct: a rung that was never tried is not a broken one, and
// a rung that answers with 195.175.254.2 is worse than one that answers not at
// all, because its answer looks like success.
func writeDNSMatrix(w io.Writer, m probe.DNSMatrix) {
	if len(m.Rows) == 0 {
		fmt.Fprintln(w, "no DNS transports were measured")
		return
	}
	fmt.Fprintf(w, "DNS transports on this network (control %s)\n\n", m.Control)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  transport\t%s\t\n", strings.Join(m.Names, "\t"))
	for _, row := range m.Rows {
		cells := make([]string, 0, len(row.Cells))
		for _, c := range row.Cells {
			cells = append(cells, c.Outcome.String())
		}
		mark := "  "
		if row.Clean {
			mark = "* "
		}
		fmt.Fprintf(tw, "%s%s\t%s\t\n", mark, row.Label, strings.Join(cells, "\t"))
	}
	tw.Flush()
	fmt.Fprintf(w, "\n  * = usable: answers the control AND returns a genuine address for a tested name\n")
	fmt.Fprintf(w, "  chain order implied by these measurements: %s\n", strings.Join(m.Order(), " → "))
}

// writeDNSHealth renders one row per rung. A rung that was never tried reports
// OK=false with no error, and must print as "untried" rather than "broken".
func writeDNSHealth(w io.Writer, hs []resolve.Health) {
	if len(hs) == 0 {
		return
	}
	fmt.Fprintln(w, "\nchain health")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, h := range hs {
		state := "untried"
		switch {
		case h.OK:
			state = "ok"
		case h.Err != nil:
			state = "broken"
		case h.Signal.Poisoned:
			state = "poisoned"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", h.Label, state, roundMillis(h.Latency), signalNote(h.Signal))
	}
	tw.Flush()
}

func signalNote(s resolve.Signal) string {
	switch {
	case s.Detail != "":
		return s.Detail
	case s.Sinkhole:
		return "answered with a known sinkhole address"
	case s.Poisoned:
		return "answer flagged as censorship"
	default:
		return ""
	}
}

// writeAAAAPolicy prints what the AAAA policy is doing, which is not visible
// from the addresses above and is the thing most likely to surprise.
//
// The two lines are deliberately separate. dpb's own lookups are protected in
// both families — whatever this process dials, it dials through the ladder — so
// the addresses printed above may include IPv6 while the answers SERVED to
// applications do not. On a v4-only capture, serving a real AAAA would hand an
// application an address for traffic dpb cannot protect, on a line where
// DOSSIER GT19 records the IPv6 sinkhole as registered to BTK itself.
func writeAAAAPolicy(w io.Writer, st resolve.AAAAStatus) {
	fmt.Fprintf(w, "\nipv6 policy: %s\n", st.Mode)
	state := "allowed"
	if !st.Served {
		state = "suppressed (NOERROR + SOA, never NXDOMAIN)"
	}
	fmt.Fprintf(w, "  AAAA served to applications: %s\n", state)
	if st.ServedWhy != "" {
		fmt.Fprintf(w, "    %s\n", st.ServedWhy)
	}
	own := "allowed"
	if !st.Own {
		own = "suppressed"
	}
	fmt.Fprintf(w, "  AAAA for dpb's own dials:    %s\n", own)
	if st.OwnWhy != "" {
		fmt.Fprintf(w, "    %s\n", st.OwnWhy)
	}
	fmt.Fprintf(w, "  IPv6 carried by this run:    %v\n", st.V6Protected)
	nat := "not detected"
	if st.NAT64.Detected {
		nat = fmt.Sprintf("detected %v", st.NAT64.Prefixes)
	}
	if st.NAT64.Detail != "" {
		nat += " (" + st.NAT64.Detail + ")"
	}
	fmt.Fprintf(w, "  NAT64/DNS64:                 %s\n", nat)
}

func newDNSResolveCmd(g *globals) *cobra.Command {
	var trace bool
	cmd := &cobra.Command{
		Use:   "resolve HOST",
		Short: "Resolve a name through dpb's chain, never the system resolver",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDNSResolve(cmd.Context(), g, args[0], trace)
		},
	}
	cmd.Flags().BoolVar(&trace, "trace", false, "show what each rung of the chain did")
	return cmd
}

func runDNSResolve(ctx context.Context, g *globals, host string, trace bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	chain, err := probeChain(g, nil)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	addrs, rerr := chain.Resolve(rctx, host)
	for _, a := range addrs {
		fmt.Fprintln(g.env.Stdout, a.String())
	}
	if trace {
		writeDNSHealth(g.env.Stdout, chain.Health())
		// The AAAA decision genuinely depends on an RFC 7050 probe, so reading
		// it can cost one query. It gets its own short budget: a diagnostic
		// that hangs on a dead network is a worse diagnostic than one that says
		// "the probe failed", which is what the status then reports.
		sctx, scancel := context.WithTimeout(ctx, 3*time.Second)
		writeAAAAPolicy(g.env.Stdout, chain.AAAAStatus(sctx))
		scancel()
	}
	if rerr != nil {
		return fmt.Errorf("dns resolve %s: %w", host, rerr)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("dns resolve %s: no addresses", host)
	}
	return nil
}
