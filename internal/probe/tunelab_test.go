package probe_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// The seed target sets, verbatim from MEASUREMENTS.md.
var (
	// §1: confirmed blocked. media.discordapp.net (401) and discord.media (520)
	// are deliberately absent — both reach the origin, and shipping them as
	// targets would make the prober chase a block that does not exist.
	labBlocked = []string{"discord.com", "discord.gg", "cdn.discordapp.com"}
	// §1 / GT1: the benign SNI, pinned to the same address as the blocked
	// targets so the only variable between the two dials is the hostname.
	labControl = "cloudflare.com"
	// The second control is an ORDINARY host that happens to break under an
	// urgent byte. It is not decoration: MEASUREMENTS.md §5.1 measures the
	// control column at 8/8 for tlsrec and chunk-12 and 6/8 for oob-at-1 and
	// oob-at-3, so a fixture with only OOB-tolerant controls omits half of the
	// measurement that decides the ladder order, and would rank the most
	// destructive rung on the ladder above the safest one.
	labControl2 = "www.google.com"
	// §5: two of the ten measured regressors. yapikredi answers a record split
	// with an explicit TLS alert; akbank fails with EOF.
	labFragile = []string{"www.yapikredi.com.tr", "www.akbank.com"}
)

// tuneLab is a whole censored line in one process.
//
// It is two middleboxes over one origin rather than one, because the two axes
// the prober scores are two different models: TT2026 is the DPI in the middle
// of the path, and Fragile is the TLS terminator at the end of it. A single
// model cannot express both — RejectSpanningRecords set on TT2026 would break
// the bypass on the blocked targets too — and the run has to see them at once
// or the two-axis result is not being tested at all.
type tuneLab struct {
	origin  *testcensor.Origin
	dpi     *testcensor.Middlebox
	term    *testcensor.Middlebox
	ctl     *testcensor.Middlebox
	termSet map[string]bool
	caps    strategy.Cap
}

// oobIntolerantControl is an ordinary TLS terminator that is broken by an
// out-of-band byte in the stream and by nothing else.
//
// It is a Model literal built from Fragile rather than an edit to any shipped
// model, and it encodes exactly one measured fact: §5.1's control column
// degrades for oob and does not degrade for record splitting or chunking.
func oobIntolerantControl() testcensor.Model {
	m := testcensor.Fragile()
	m.Name = "oob-intolerant-control"
	m.Doc = "ordinary host broken by an urgent byte; MEASUREMENTS.md §5.1 controls 6/8 for oob-at-1"
	m.RejectSpanningRecords = false
	m.Action = testcensor.ActionReset
	m.AlertDesc = 0
	return m
}

func newTuneLab(t *testing.T, dpi, term testcensor.Model) *tuneLab {
	t.Helper()
	names := append([]string(nil), labBlocked...)
	names = append(names, labControl, labControl2)
	names = append(names, labFragile...)

	o, err := testcensor.NewOrigin(testcensor.OriginConfig{Names: names})
	if err != nil {
		t.Fatalf("origin: %v", err)
	}
	t.Cleanup(func() { o.Close() })

	set := make(map[string]bool, len(labFragile))
	for _, h := range labFragile {
		set[h] = true
	}
	return &tuneLab{
		origin: o,
		// Port 443 is asserted rather than inferred: the origin binds an
		// ephemeral loopback port, and a model scoped to 443 would otherwise
		// inspect nothing at all — silently, and in the direction that makes
		// every test pass.
		dpi:     testcensor.New(dpi, testcensor.Options{Port: 443, Logf: t.Logf}),
		term:    testcensor.New(term, testcensor.Options{Port: 443, Logf: t.Logf}),
		ctl:     testcensor.New(oobIntolerantControl(), testcensor.Options{Port: 443, Logf: t.Logf}),
		termSet: set,
		caps:    strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL | strategy.CapOOB,
	}
}

// DialTCP routes each flow to the model that owns its destination.
func (l *tuneLab) DialTCP(ctx context.Context, t flow.Target) (net.Conn, error) {
	box := l.dpi
	switch {
	case l.termSet[t.Name]:
		box = l.term
	case t.Name == labControl2:
		box = l.ctl
	}
	return box.DialContext(ctx, "tcp", l.origin.Addr())
}

func (l *tuneLab) addr() string {
	h, _, err := net.SplitHostPort(l.origin.Addr())
	if err != nil {
		return "127.0.0.1"
	}
	return h
}

// targets is the seeded target set, every entry pinned by address.
func (l *tuneLab) port() int {
	_, p, err := net.SplitHostPort(l.origin.Addr())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func (l *tuneLab) targets() []probe.Target {
	addr := l.addr()
	out := make([]probe.Target, 0, len(labBlocked)+1+len(labFragile))
	for _, h := range labBlocked {
		out = append(out, probe.Target{Host: h, Kind: probe.TargetBlocked, Addr: addr})
	}
	// labControl is first, so it is the one the benign-SNI baseline and the
	// per-round liveness probe use: it must be a host that plain always reaches.
	out = append(out, probe.Target{Host: labControl, Kind: probe.TargetControl, Addr: addr})
	out = append(out, probe.Target{Host: labControl2, Kind: probe.TargetControl, Addr: addr})
	for _, h := range labFragile {
		out = append(out, probe.Target{Host: h, Kind: probe.TargetFragile, Addr: addr})
	}
	return out
}

func (l *tuneLab) options(t *testing.T) probe.Options {
	t.Helper()
	return probe.Options{
		Targets:  l.targets(),
		Registry: reg,
		Dial:     l,
		Caps:     l.caps,
		// An ungoverned Sender: the prober must emit exactly the segments it
		// claims to have emitted or the measurement is a lie.
		Sender:    &emit.Sender{Logf: t.Logf},
		Wrap:      func(c net.Conn) (emit.Transport, error) { return newBoxTransport(c, l.caps) },
		TLSConfig: func(host string) *tls.Config { return l.origin.ClientConfig(host) },
		Timeout:   5 * time.Second,
		// The cooldown is anti-noise on a real line and pure wall-clock here.
		Cooldown: time.Nanosecond,
		Logf:     t.Logf,
	}
}

// rankOf is the 1-based position of a spec in a ranking, or 0.
func rankOf(scores []probe.Score, spec string) int {
	for i, s := range scores {
		if s.Spec == spec {
			return i + 1
		}
	}
	return 0
}

func scoreOf(t *testing.T, scores []probe.Score, spec string) probe.Score {
	t.Helper()
	for _, s := range scores {
		if s.Spec == spec {
			return s
		}
	}
	t.Fatalf("no score for %q; have %s", spec, specList(scores))
	return probe.Score{}
}

func specList(scores []probe.Score) string {
	out := make([]string, 0, len(scores))
	for _, s := range scores {
		out = append(out, s.Label())
	}
	return strings.Join(out, ", ")
}

// loopbackPrefix is every address this fixture can possibly dial, which is what
// makes testcensor.IPBlock model an address-level block here.
var loopbackPrefix = netip.MustParsePrefix("127.0.0.0/8")

// opsExcept is the shipped op set minus one, for asserting how the classifier
// behaves when a mechanism probe is not available in a build.
func opsExcept(name string) []strategy.Op {
	var out []strategy.Op
	for _, op := range ops.All() {
		if op.Name() != name {
			out = append(out, op)
		}
	}
	return out
}
