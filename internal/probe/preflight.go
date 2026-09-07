package probe

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/miekg/dns"

	"github.com/mumudevx/dpb/internal/resolve"
)

// DNSOutcome is what one resolver did with one name.
type DNSOutcome uint8

const (
	// DNSUntried is a cell that was never asked, which renders as "-" and not
	// as a failure. A never-tried rung reported as broken is how a matrix
	// invents a network problem.
	DNSUntried DNSOutcome = iota
	DNSOK
	DNSTimeout
	DNSSinkhole
	DNSRcode
	DNSEmpty
	DNSError
)

var dnsOutcomeNames = [...]string{
	"-", "ok", "timeout", "SINKHOLE", "rcode", "empty", "error",
}

func (o DNSOutcome) String() string {
	if int(o) >= len(dnsOutcomeNames) {
		return "invalid"
	}
	return dnsOutcomeNames[o]
}

// DNSCell is one (resolver, name) measurement.
type DNSCell struct {
	Name    string
	Outcome DNSOutcome
	Rcode   int
	Addrs   []netip.Addr
	Latency time.Duration
	Err     string
}

// DNSRow is one resolver's row of the phase-1 matrix.
type DNSRow struct {
	Label     string
	Transport string
	Cells     []DNSCell
	// Clean means this transport answered the control AND returned a genuine
	// address for at least one name the rest of the run cares about. A resolver
	// that answers google.com and drops every blocked name is live but useless,
	// and the distinction is the whole reason MEASUREMENTS.md §2 lists both
	// columns.
	Clean bool
}

// DNSMatrix is phase 1: every transport against the control and the blocked
// names, on this line, rather than the same table taken from the dossier.
type DNSMatrix struct {
	Control string
	Names   []string
	Rows    []DNSRow
}

// CleanCount is how many transports came back clean.
func (m DNSMatrix) CleanCount() int {
	n := 0
	for _, r := range m.Rows {
		if r.Clean {
			n++
		}
	}
	return n
}

// Order is the resolver chain the matrix implies: clean transports first,
// fastest first, then everything else in its configured order.
//
// It is derived from the measurements already taken rather than from
// resolve.Rank, which would re-probe the same resolvers with the same control
// to learn the same thing. Rank remains the right tool for a caller that has no
// matrix; here it would be a second round trip per rung for no new evidence.
func (m DNSMatrix) Order() []string {
	type row struct {
		idx     int
		clean   bool
		latency time.Duration
		label   string
	}
	rs := make([]row, 0, len(m.Rows))
	for i, r := range m.Rows {
		rs = append(rs, row{idx: i, clean: r.Clean, latency: r.controlLatency(m.Control), label: r.Label})
	}
	sort.SliceStable(rs, func(a, b int) bool {
		if rs[a].clean != rs[b].clean {
			return rs[a].clean
		}
		if !rs[a].clean {
			return false // dead transports keep their configured order
		}
		return rs[a].latency < rs[b].latency
	})
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.label)
	}
	return out
}

func (r DNSRow) controlLatency(control string) time.Duration {
	for _, c := range r.Cells {
		if c.Name == control {
			return c.Latency
		}
	}
	return time.Duration(1<<62 - 1)
}

// dnsProbeTimeout bounds one (resolver, name) query.
//
// MEASUREMENTS.md §2 measures the censorship of a blocked name as a per-QNAME
// DROP, so the expected failure of an interesting cell is silence. Two seconds
// is long enough that a slow but working transport is not called dead and short
// enough that a full matrix of seven transports and four names is a few seconds
// rather than a minute.
const dnsProbeTimeout = 2 * time.Second

// dnsProbeNames caps how many blocked names go into the matrix. Three is what
// §2 measured and what the shipped poison probes use; more is more waiting for
// no new partition of the hypothesis space.
const dnsProbeNames = 3

// Preflight measures the DNS transport matrix and reports one Health row per
// resolver, in chain order.
//
// It returns resolve.ErrNoCleanTransport when every transport is either dropped
// or poisoned. That is a stop condition, not a warning: no packet strategy
// fixes a poisoned resolver, so continuing would measure emitters against
// whatever the censor's address answers with — which is exactly the defect
// MEASUREMENTS.md §5.4 records, a whole matrix scoring 0/6 against a sinkhole.
func (r *Runner) Preflight(ctx context.Context) ([]resolve.Health, error) {
	m := DNSMatrix{Control: r.dnsControl()}
	m.Names = append(m.Names, m.Control)
	for _, t := range r.o.Targets {
		if t.Kind != TargetBlocked || len(m.Names) > dnsProbeNames {
			continue
		}
		if t.Host != m.Control {
			m.Names = append(m.Names, t.Host)
		}
	}

	if len(r.o.Resolvers) == 0 {
		// No chain to measure. That is legitimate — every target may be pinned,
		// which is the mode `dpb probe --addr` and the offline tests run in —
		// but it must be said out loud rather than reported as a clean matrix.
		r.matrix = m
		r.warn("no resolver chain was configured, so the DNS transport matrix was not measured; " +
			"targets must be pinned with an explicit address")
		return nil, nil
	}

	for _, res := range r.o.Resolvers {
		row := DNSRow{Label: res.Label(), Transport: res.Transport()}
		for _, name := range m.Names {
			row.Cells = append(row.Cells, r.dnsCell(ctx, res, name))
		}
		row.Clean = rowClean(row, m.Control)
		m.Rows = append(m.Rows, row)
	}
	r.matrix = m

	health := make([]resolve.Health, 0, len(m.Rows))
	for _, row := range m.Rows {
		health = append(health, rowHealth(row, m.Control))
	}
	r.dns = health

	if m.CleanCount() == 0 {
		return health, fmt.Errorf("%w: %d transport(s) tried, none returned a genuine answer for %s",
			resolve.ErrNoCleanTransport, len(m.Rows), joinNames(m.Names))
	}
	return health, nil
}

// Matrix is the phase-1 table Preflight measured. It is empty before Preflight
// runs.
func (r *Runner) Matrix() DNSMatrix { return r.matrix }

func (r *Runner) dnsControl() string {
	if r.o.DNSControl != "" {
		return r.o.DNSControl
	}
	for _, t := range r.o.Targets {
		if t.Kind == TargetControl && t.Host != "" {
			return t.Host
		}
	}
	// MEASUREMENTS.md §2 uses google.com against every transport for exactly
	// this: a control that is blocked here would rank every working resolver
	// dead, which is the failure mode a preflight must not have.
	return "google.com"
}

func (r *Runner) dnsCell(ctx context.Context, res resolve.Resolver, name string) DNSCell {
	c := DNSCell{Name: name}
	q, err := resolve.NewQuery(name, dns.TypeA)
	if err != nil {
		c.Outcome, c.Err = DNSError, err.Error()
		return c
	}
	qctx, cancel := context.WithTimeout(ctx, dnsProbeTimeout)
	defer cancel()

	start := r.now()
	ans, err := res.Exchange(qctx, q)
	c.Latency = r.now().Sub(start)
	if err != nil {
		c.Err = err.Error()
		if qctx.Err() != nil {
			c.Outcome = DNSTimeout
		} else {
			c.Outcome = DNSError
		}
		return c
	}
	c.Rcode = resolve.Rcode(ans)
	c.Addrs = resolve.AnswerAddrs(ans)
	switch {
	case c.Rcode != dns.RcodeSuccess:
		c.Outcome = DNSRcode
	case len(c.Addrs) == 0:
		c.Outcome = DNSEmpty
	case anySinkhole(c.Addrs, r.sinkholes()):
		c.Outcome = DNSSinkhole
	default:
		c.Outcome = DNSOK
	}
	return c
}

// rowClean applies the two-part test: the transport must answer the control,
// and it must return a genuine address for at least one of the names the run
// is actually about.
func rowClean(row DNSRow, control string) bool {
	controlOK, interesting := false, false
	for _, c := range row.Cells {
		if c.Name == control {
			controlOK = c.Outcome == DNSOK
			continue
		}
		if c.Outcome == DNSOK {
			interesting = true
		}
	}
	if !controlOK {
		return false
	}
	// A matrix run with only the control column has no blocked name to
	// separate "live" from "useful". Answering the control is then all the
	// evidence there is, and it is enough to keep the transport.
	if !hasOther(row, control) {
		return true
	}
	return interesting
}

func hasOther(row DNSRow, control string) bool {
	for _, c := range row.Cells {
		if c.Name != control {
			return true
		}
	}
	return false
}

func rowHealth(row DNSRow, control string) resolve.Health {
	h := resolve.Health{Label: row.Label}
	for _, c := range row.Cells {
		if c.Name == control {
			h.OK = c.Outcome == DNSOK
			h.Latency = c.Latency
			if c.Err != "" {
				h.Err = fmt.Errorf("%s: %s", c.Name, c.Err)
			}
		}
		if c.Outcome == DNSSinkhole {
			h.Signal = resolve.Signal{
				Poisoned: true,
				Sinkhole: true,
				Addr:     firstSinkhole(c.Addrs),
				Detail: fmt.Sprintf("%s answered %s with a known sinkhole address (MEASUREMENTS.md §2)",
					row.Label, c.Name),
			}
		}
	}
	return h
}

func anySinkhole(addrs []netip.Addr, set []netip.Addr) bool {
	for _, a := range addrs {
		if isSinkhole(a, set) {
			return true
		}
	}
	return false
}

func firstSinkhole(addrs []netip.Addr) netip.Addr {
	for _, a := range addrs {
		if isSinkhole(a, resolve.DefaultSinkholes) {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return netip.Addr{}
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return "any name"
	case 1:
		return names[0]
	default:
		out := names[0]
		for _, n := range names[1:] {
			out += ", " + n
		}
		return out
	}
}
