package cliapp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/ops"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// sampleSNI is the name a synthesised sample ClientHello carries when the user
// gives none. It is a measured-blocked host (MEASUREMENTS.md §1) so the printed
// plan is the plan for the case the tool exists to handle.
const sampleSNI = "discord.com"

func newStrategyCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "strategy",
		Short:   "Inspect the emitter set and what a spec compiles to",
		Aliases: []string{"strategies"},
	}
	cmd.AddCommand(
		newStrategyListCmd(g),
		newStrategyExplainCmd(g),
		newStrategyPlanCmd(g),
		newStrategyValidateCmd(g),
	)
	return cmd
}

func newStrategyListCmd(g *globals) *cobra.Command {
	var ladder string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every registered op, or the rungs of a ladder",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			reg := ops.Install()
			if ladder != "" {
				return listLadder(g.env.Stdout, reg, ladder)
			}
			listOps(g.env.Stdout, reg)
			return nil
		},
	}
	cmd.Flags().StringVar(&ladder, "ladder", "",
		"list the rungs of a named ladder instead ("+strings.Join(strategy.LadderNames(), ", ")+")")
	return cmd
}

func listOps(w io.Writer, reg *strategy.Registry) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "OP\tKIND\tBASIS\tRISK\tCAPS\tSOURCE")
	for _, d := range reg.Docs() {
		basis := d.Determinism.String()
		if d.Rejected != "" {
			basis = "rejected"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			d.Name, d.Kind, basis, d.Risk, d.Caps, d.Source)
	}
	tw.Flush()

	// A rejected op is registered on purpose: asking for it must produce a
	// cited refusal rather than "unknown op", so the reason is worth printing.
	var rejected []strategy.OpDoc
	for _, d := range reg.Docs() {
		if d.Rejected != "" {
			rejected = append(rejected, d)
		}
	}
	if len(rejected) == 0 {
		return
	}
	fmt.Fprintln(w, "\nregistered but never usable here:")
	for _, d := range rejected {
		fmt.Fprintf(w, "  %-12s %s\n", d.Name, d.Rejected)
	}
}

func listLadder(w io.Writer, reg *strategy.Registry, name string) error {
	rungs, err := reg.Ladder(name)
	if err != nil {
		return usagef("%v", err)
	}
	fmt.Fprintf(w, "ladder %s\n", name)
	for i, s := range rungs {
		fmt.Fprintf(w, "  %d. %s\n", i+1, s.Label())
	}
	return nil
}

func newStrategyExplainCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "explain SPEC",
		Short: "Say what a spec does, op by op, with its evidence",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := ops.Install().Get(args[0])
			if err != nil {
				return usagef("%v", err)
			}
			for _, line := range s.Explain() {
				fmt.Fprintln(g.env.Stdout, line)
			}
			return nil
		},
	}
}

func newStrategyPlanCmd(g *globals) *cobra.Command {
	var sample, sni string
	cmd := &cobra.Command{
		Use:   "plan SPEC",
		Short: "Compile a spec against a sample first message and print the segments",
		Long: "plan shows the exact bytes a spec would put on the wire, without a network.\n" +
			"The plan is a value: the same one the proxy emits, so what is printed here is\n" +
			"what a connection would send.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := ops.Install().Get(args[0])
			if err != nil {
				return usagef("%v", err)
			}
			payload, port, err := samplePayload(sample, sni)
			if err != nil {
				return err
			}
			m := tlsmsg.Parse(payload, port)
			plan, err := buildStrict(s, payload, m)
			if err != nil {
				return err
			}
			printPlan(g.env.Stdout, s, m, len(payload), plan)
			return nil
		},
	}
	cmd.Flags().StringVar(&sample, "sample", "tls", "sample first message: tls | http")
	cmd.Flags().StringVar(&sni, "sni", sampleSNI, "hostname carried by the sample")
	return cmd
}

func newStrategyValidateCmd(g *globals) *cobra.Command {
	var sample, sni string
	cmd := &cobra.Command{
		Use:   "validate SPEC",
		Short: "Check that a spec parses, is composable and can be emitted here",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := ops.Install().Get(args[0])
			if err != nil {
				return usagef("%v", err)
			}
			payload, port, err := samplePayload(sample, sni)
			if err != nil {
				return err
			}
			m := tlsmsg.Parse(payload, port)
			if _, err := buildStrict(s, payload, m); err != nil {
				return err
			}
			fmt.Fprintf(g.env.Stdout, "ok: %s compiles against a %s first message for %s\n",
				s.Label(), sample, sni)
			return nil
		},
	}
	cmd.Flags().StringVar(&sample, "sample", "tls", "sample first message: tls | http")
	cmd.Flags().StringVar(&sni, "sni", sampleSNI, "hostname carried by the sample")
	return cmd
}

// buildStrict compiles a spec the way the prober does: any downgrade is an
// error. `dpb strategy plan` printing a silently degraded plan would be worse
// than printing nothing, because the user would go on to trust it.
func buildStrict(s strategy.Strategy, payload []byte, m tlsmsg.Meta) (strategy.Plan, error) {
	b := &strategy.Builder{
		Payload: append([]byte(nil), payload...),
		Meta:    m,
		Caps:    localCaps(),
		Strict:  true,
	}
	// BuildWith already names the spec and the failing op, so this returns the
	// error as it stands rather than repeating the label.
	return s.BuildWith(b)
}

// localCaps is what a kernel socket on this build offers. It is asked of a real
// transport rather than assumed, so a capability withheld on this platform
// (emit.stub_other) shows up here as a refusal rather than as a plan that
// cannot be emitted.
func localCaps() strategy.Cap {
	c, err := loopbackCaps()
	if err != nil {
		// Falling back to the two capabilities every stream socket has keeps
		// `strategy plan` usable with no network at all; anything needing more
		// then fails validation with a named missing capability.
		return strategy.CapStreamWrite | strategy.CapNoDelay
	}
	return c
}

// printPlan reports the original message length and the emitted length
// separately. A reframing op adds record headers, so conflating the two would
// hide the five bytes that are the whole mechanism.
func printPlan(w io.Writer, s strategy.Strategy, m tlsmsg.Meta, origLen int, p strategy.Plan) {
	fmt.Fprintf(w, "spec      %s\n", s.Label())
	fmt.Fprintf(w, "message   %s, %d bytes in, %d bytes out, complete=%v",
		m.Proto, origLen, len(p.Payload), m.Complete)
	if m.HasSNI() {
		end, _ := m.MaxFirstRecordEnd()
		fmt.Fprintf(w, ", sni %q at body [%d,%d) — first record must end at or before %d",
			m.ServerName, m.SNIStart, m.SNIEnd, end)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "writes    %d\n\n", p.WriteCount())

	for i, seg := range p.Segments {
		fmt.Fprintf(w, "  %2d. %-9s %5d bytes", i+1, seg.Kind, len(seg.Data))
		if seg.TTL != 0 {
			fmt.Fprintf(w, " ttl=%d", seg.TTL)
		}
		if seg.Delay > 0 {
			fmt.Fprintf(w, " delay=%s", seg.Delay.Round(time.Millisecond))
		}
		if seg.Note != "" {
			fmt.Fprintf(w, "  %s", seg.Note)
		}
		fmt.Fprintln(w)
	}
	for _, n := range p.Notes {
		fmt.Fprintf(w, "\nnote: %s\n", n)
	}
}

// samplePayload returns a first message to compile against.
//
// The TLS sample is generated by crypto/tls itself rather than hand-built: the
// point of `strategy plan` is to show what happens to a real ClientHello, and a
// hand-rolled one would drift from what the shipped TLS stack actually emits —
// including its length, which is what the record rule is expressed against.
func samplePayload(kind, sni string) ([]byte, int, error) {
	if sni == "" {
		sni = sampleSNI
	}
	switch strings.ToLower(kind) {
	case "tls", "":
		b, err := sampleClientHello(sni)
		if err != nil {
			return nil, 0, err
		}
		return b, 443, nil
	case "http":
		req := "GET / HTTP/1.1\r\nHost: " + sni + "\r\nUser-Agent: dpb\r\nAccept: */*\r\n\r\n"
		return []byte(req), 80, nil
	default:
		return nil, 0, usagef("strategy: --sample must be tls or http, got %q", kind)
	}
}

func sampleClientHello(sni string) ([]byte, error) {
	c := &captureConn{}
	// The handshake cannot complete against a conn that never answers; the
	// ClientHello is written before that matters, which is exactly the byte
	// string wanted here.
	err := tls.Client(c, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}).Handshake()
	if len(c.written) == 0 {
		if err == nil {
			err = errors.New("no bytes written")
		}
		return nil, fmt.Errorf("strategy: synthesise a ClientHello for %q: %w", sni, err)
	}
	return c.written, nil
}

// captureConn records what a TLS client writes and refuses to read, so a
// handshake stops after its first flight with no goroutine and no socket.
type captureConn struct {
	written []byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.written = append(c.written, b...)
	return len(b), nil
}
func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return sampleAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return sampleAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type sampleAddr struct{}

func (sampleAddr) Network() string { return "sample" }
func (sampleAddr) String() string  { return "sample" }

// loopbackCaps asks a real emit.SockTransport what a kernel socket on this
// build offers, rather than hardcoding a list. It opens one loopback
// connection, reads the capability set and closes it: no traffic leaves the
// machine and nothing is mutated.
func loopbackCaps() (strategy.Cap, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("cliapp: loopback listen: %w", err)
	}
	defer ln.Close()

	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("cliapp: loopback listener has a %T address", ln.Addr())
	}
	c, err := net.DialTCP("tcp", nil, ta)
	if err != nil {
		return 0, fmt.Errorf("cliapp: loopback dial: %w", err)
	}
	defer c.Close()

	t, err := emit.NewSockTransport(c, nil)
	if err != nil {
		return 0, fmt.Errorf("cliapp: wrap loopback socket: %w", err)
	}
	return t.Caps(), nil
}
