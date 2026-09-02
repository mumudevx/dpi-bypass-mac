package cliapp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// `dpb selftest` runs the censor-simulator matrix inside the shipped binary.
//
// It exists because "does this build actually work" is a question a user in
// Turkey has to be able to answer without a censored line and without the Go
// toolchain. Every claim it checks is one MEASUREMENTS.md makes, and every one
// is run through the SAME datapath a real connection uses: the real strategy
// compiler, the real emit.Sender over the real capabilities, and probe.RunTrial
// doing a real TLS handshake with full certificate verification. The only thing
// substituted is the middlebox, which is the point.
//
// What it does NOT test is whether a strategy defeats real Turkish DPI. The
// models are hypotheses about a middlebox, not the middlebox, and a green
// selftest on a censored line that has changed proves only that the code still
// does what it was measured to do in September 2026.

// selftestCase is one claim, with the measurement it comes from.
type selftestCase struct {
	Model string `json:"model"`
	Spec  string `json:"spec"`
	Host  string `json:"host"`
	// Want is the verdict the measurement predicts.
	Want string `json:"want"`
	Got  string `json:"got"`
	OK   bool   `json:"ok"`
	// Because names the measurement, so a failure is traceable to a claim
	// rather than to a number somebody once typed.
	Because string `json:"because"`
	Err     string `json:"error,omitempty"`
}

type selftestReport struct {
	Cases  []selftestCase `json:"cases"`
	Passed int            `json:"passed"`
	Failed int            `json:"failed"`
}

// selftestNames are the hostnames the fixture origin answers for.
const (
	selftestBlocked = "discord.com"
	selftestControl = "cloudflare.com"
	selftestBank    = "www.yapikredi.com.tr"
)

func newSelftestCmd(g *globals) *cobra.Command {
	var (
		model  string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Run the censor-simulator matrix in this binary",
		Long: "selftest checks that this build still behaves the way MEASUREMENTS.md says it\n" +
			"should, against an in-process censor. It needs no network, no root and no\n" +
			"censored line.\n\n" +
			"Each case is a claim with its measurement attached: that tlsfrag:pos=snimid\n" +
			"defeats a first-record-only DPI, that plain does not, that a benign SNI to the\n" +
			"same address is never touched, and that a bank which rejects a split handshake\n" +
			"is reached on the plain rung and broken by the desynced one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSelftest(cmd.Context(), g, model, asJSON)
		},
	}
	cmd.Flags().StringVar(&model, "model", "", "run only the cases for one model (tt2026 | fragile)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the matrix as JSON")
	return cmd
}

func runSelftest(ctx context.Context, g *globals, model string, asJSON bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ops.Install()

	cases, err := selftestMatrix(ctx, model)
	if err != nil {
		return err
	}
	rep := selftestReport{Cases: cases}
	for _, c := range cases {
		if c.OK {
			rep.Passed++
		} else {
			rep.Failed++
		}
	}

	if asJSON {
		enc := json.NewEncoder(g.env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fmt.Errorf("selftest: write JSON: %w", err)
		}
	} else {
		writeSelftest(g.env.Stdout, rep)
	}
	if rep.Failed > 0 {
		return fmt.Errorf("selftest: %d of %d case(s) failed", rep.Failed, len(rep.Cases))
	}
	return nil
}

// claim is one row of the matrix before it is run.
type claim struct {
	model   testcensor.Model
	spec    string
	host    string
	want    probe.Verdict
	because string
}

// selftestClaims is the matrix. Every row is a sentence from MEASUREMENTS.md.
func selftestClaims() []claim {
	tt := testcensor.TT2026(selftestBlocked)
	fragile := testcensor.Fragile()
	return []claim{
		{
			model: tt, spec: "", host: selftestBlocked, want: probe.VerdictReset,
			because: "§1: discord.com is RST on 443 with no desync",
		},
		{
			model: tt, spec: "tlsfrag:pos=snimid", host: selftestBlocked, want: probe.VerdictPass,
			because: "§3.2: the DPI parses only the first TLS record, so a cut before sniEnd passes (6/6)",
		},
		{
			model: tt, spec: "", host: selftestControl, want: probe.VerdictPass,
			because: "§1 / GT1: a benign SNI to the same address returns the origin, so the block is SNI-keyed",
		},
		{
			model: tt, spec: "tlsevery:period=64", host: selftestBlocked, want: probe.VerdictPass,
			because: "§3.2: tlsrec-every-64 passes because the first record ends at 64 <= sniEnd-1",
		},
		{
			model: tt, spec: "oob:pos=1", host: selftestBlocked, want: probe.VerdictPass,
			because: "§3 / §5.1: oob-at-1 is 6/6 through — an urgent byte the middlebox reads " +
				"inline and the receiving TCP never delivers",
		},
		{
			// This one pins a deliberate LIMIT of the model rather than a bypass.
			// §3.4 measured chunk-4 and chunk-12 through and chunk-5, -8, -20 and
			// -40 blocked, which is non-monotonic in both size and count and which
			// no rule explains; testcensor.TT2026 therefore does not reproduce it,
			// and chunking is honestly a non-bypass there. Asserting that keeps
			// somebody from "fixing" the model into a lookup table.
			model: tt, spec: "chunk:size=12", host: selftestBlocked, want: probe.VerdictReset,
			because: "§3.4 is non-monotonic and unexplained, so TT2026 deliberately does not " +
				"model chunking as a bypass; the ladder keeps it as a measured fallback rung",
		},
		{
			model: fragile, spec: "oob:pos=1", host: selftestBank, want: probe.VerdictReset,
			because: "§5.1: oob-at-1 scores 0/20 on the fragile axis — it is the most " +
				"destructive rung and is last on the ladder for exactly this reason",
		},
		{
			model: fragile, spec: "", host: selftestBank, want: probe.VerdictPass,
			because: "§5.1: every fragile host is 20/20 on the plain rung; default-direct is a " +
				"correctness requirement, not an optimisation",
		},
		{
			model: fragile, spec: "tlsfrag:pos=snimid", host: selftestBank, want: probe.VerdictHandshakeFail,
			because: "§5: www.yapikredi.com.tr answers a split ClientHello with " +
				"'tls: illegal parameter'; this is the case a shipped exclusion list cannot cover",
		},
	}
}

// selftestMatrix runs every claim, or only the ones for one model.
func selftestMatrix(ctx context.Context, only string) ([]selftestCase, error) {
	claims := selftestClaims()
	if only != "" {
		var kept []claim
		for _, c := range claims {
			if strings.EqualFold(c.model.Name, only) {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			var names []string
			seen := map[string]bool{}
			for _, c := range claims {
				if !seen[c.model.Name] {
					seen[c.model.Name] = true
					names = append(names, c.model.Name)
				}
			}
			sort.Strings(names)
			return nil, usagef("selftest: no model named %q (have %s)", only, strings.Join(names, ", "))
		}
		claims = kept
	}

	// One origin for every case: the fixture's whole point is that the blocked
	// name and the benign control resolve to the SAME address, which is GT1's
	// experiment and the only way to isolate the SNI from every routing
	// variable.
	line, err := newCensorLine()
	if err != nil {
		return nil, err
	}
	defer line.close()

	reg := ops.NewRegistry()
	out := make([]selftestCase, 0, len(claims))
	for _, c := range claims {
		row := selftestCase{
			Model: c.model.Name, Spec: specLabel(c.spec), Host: c.host,
			Want: c.want.String(), Because: c.because,
		}
		s, perr := reg.Get(c.spec)
		if perr != nil {
			row.Err = perr.Error()
			row.Got = probe.VerdictLocalError.String()
			out = append(out, row)
			continue
		}
		tr := probe.RunTrial(ctx, s, probe.Target{
			Host: c.host,
			Port: line.port(),
			Addr: "127.0.0.1",
		}, 0, line.options(c.model))
		row.Got = tr.Verdict.String()
		row.Err = tr.Err
		row.OK = tr.Verdict == c.want
		out = append(out, row)
	}
	return out, nil
}

// censorLine is a whole censored line in one process: a real TLS origin on
// loopback, reached through a middlebox that enforces a model.
type censorLine struct {
	origin *testcensor.Origin
	caps   strategy.Cap
	mu     sync.Mutex
}

func newCensorLine() (*censorLine, error) {
	o, err := testcensor.NewOrigin(testcensor.OriginConfig{
		Names: []string{selftestBlocked, selftestControl, selftestBank},
	})
	if err != nil {
		return nil, fmt.Errorf("selftest: start the fixture origin: %w", err)
	}
	return &censorLine{
		origin: o,
		// The capabilities an ordinary kernel socket grants, so a plan that
		// would be downgraded in production is downgraded here too.
		caps: proxyCaps,
	}, nil
}

func (l *censorLine) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.origin != nil {
		_ = l.origin.Close()
		l.origin = nil
	}
}

// port is the origin's loopback port. The model is told about 443 separately,
// because a model scoped to 443 would otherwise inspect nothing at all —
// silently, and in the direction that makes every case pass.
func (l *censorLine) port() int {
	if ap, err := netip.ParseAddrPort(l.origin.Addr()); err == nil {
		return int(ap.Port())
	}
	return 0
}

func (l *censorLine) options(m testcensor.Model) probe.TrialOptions {
	box := testcensor.New(m, testcensor.Options{Port: 443})
	return probe.TrialOptions{
		Dial: boxDialer{box: box, addr: l.origin.Addr()},
		Wrap: func(c net.Conn) (emit.Transport, error) { return newBoxTransport(c, l.caps) },
		// Full verification against the fixture's own certificate. PASS has to
		// keep meaning "the handshake completed AND the certificate validates
		// for the name" here, or the selftest is checking something weaker than
		// the live probe does.
		TLSConfig: func(host string) *tls.Config { return l.origin.ClientConfig(host) },
		// A prober must emit exactly the segments it claims to have emitted, so
		// no governor: a coalesced plan is not the plan that was asked for.
		Sender: &emit.Sender{},
	}
}

// boxDialer routes every dial through the middlebox, so the model applies to
// exactly the connection under test and to nothing else.
type boxDialer struct {
	box  *testcensor.Middlebox
	addr string
}

func (d boxDialer) DialTCP(ctx context.Context, _ flow.Target) (net.Conn, error) {
	// The address is the Addr() of a listener this process bound on
	// 127.0.0.1:0, so it is always an IP literal; see the entry recorded for
	// this file in internal/flow/nohostdial_test.go's reviewedAddrExprs.
	return d.box.DialContext(ctx, "tcp", d.addr)
}

// boxTransport adapts a testcensor.Conn to emit.Transport. It is the only piece
// of the datapath the selftest substitutes: the plan, the Sender and the
// emission order are the shipped ones.
type boxTransport struct {
	c    testcensor.Conn
	caps strategy.Cap
}

func newBoxTransport(c net.Conn, caps strategy.Cap) (emit.Transport, error) {
	cc, ok := c.(testcensor.Conn)
	if !ok {
		return nil, errors.New("selftest: the fixture dialler did not return a testcensor.Conn")
	}
	return &boxTransport{c: cc, caps: caps}, nil
}

func (t *boxTransport) Caps() strategy.Cap              { return t.caps }
func (t *boxTransport) Write(b []byte) (int, error)     { return t.c.Write(b) }
func (t *boxTransport) WriteOOB(b []byte) (int, error)  { return t.c.WriteOOB(b) }
func (t *boxTransport) SetTTL(ttl int) error            { return t.c.SetTTL(ttl) }
func (t *boxTransport) ResetTTL() error                 { return t.c.SetTTL(0) }
func (t *boxTransport) InjectRaw([]byte) error          { return emit.ErrCapUnavailable }
func (t *boxTransport) SeqState() (emit.SeqState, bool) { return emit.SeqState{}, false }
func (t *boxTransport) Local() netip.AddrPort           { return addrPortOf(t.c.LocalAddr()) }
func (t *boxTransport) Remote() netip.AddrPort          { return addrPortOf(t.c.RemoteAddr()) }
func (t *boxTransport) Close() error                    { return t.c.Close() }

func addrPortOf(a net.Addr) netip.AddrPort {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(ta.Port))
}

func writeSelftest(w io.Writer, rep selftestReport) {
	var b strings.Builder
	for _, c := range rep.Cases {
		mark := "FAIL"
		if c.OK {
			mark = "ok  "
		}
		fmt.Fprintf(&b, "[%s] %-14s %-22s %-22s want %-14s got %s\n",
			mark, c.Model, c.Spec, c.Host, c.Want, c.Got)
		if !c.OK {
			// A failing claim is only useful with the measurement it came from:
			// it tells the reader whether the code regressed or the model is
			// being asked something it never claimed.
			fmt.Fprintf(&b, "       claim: %s\n", c.Because)
			if c.Err != "" {
				fmt.Fprintf(&b, "       error: %s\n", c.Err)
			}
		}
	}
	fmt.Fprintf(&b, "\n%d case(s), %d passed, %d failed\n", len(rep.Cases), rep.Passed, rep.Failed)
	_, _ = io.WriteString(w, b.String())
}
