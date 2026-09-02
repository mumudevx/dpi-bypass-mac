package observ

import (
	"sort"
	"sync"
	"time"
)

// Counters is the rolling record of what the ladder actually did, and the
// drift detector built on top of it.
//
// It answers the three questions a user in Turkey actually asks. "Nothing
// works" is answered by the global outcome mix. "My bank broke" is answered by
// Recent(host), which `dpb why` prints under the verdict that caused it. "It
// worked yesterday" is answered by the drift detector: when most of the hosts
// dpb is judging suddenly need a desync they did not need before, the ISP's DPI
// has changed and no amount of staring at one connection will show it.
//
// Everything is bounded. A laptop left running for a week must not accumulate
// an unbounded map keyed by every hostname a browser touched, so hosts are
// LRU-capped and per-host display history is a small ring.

// Drift defaults. The window and the threshold are sizing choices, not
// measurements, and are labelled as such: docs/PLAN.md's rule is "more than two
// thirds of in-scope hosts in a rolling window escalate past the persisted
// default", which fixes the shape but not the numbers.
const (
	DefaultDriftWindow   = 30 * time.Minute
	DefaultDriftRate     = 2.0 / 3.0
	DefaultDriftMinHosts = 6
	DefaultDriftCooldown = time.Hour

	// DefaultCounterHostCap bounds the host table. A browsing session touches
	// far fewer than this; the cap only stops unbounded growth on a machine
	// left running for days.
	DefaultCounterHostCap = 1024
	// DefaultRecentPerHost is how many outcomes `dpb why` can show for one
	// host. Enough to see a pattern, few enough to read.
	DefaultRecentPerHost = 8
)

// DriftRemedy is the sentence every surface prints when drift is suspected. It
// lives on the event rather than at each call site so the log, the event log,
// `dpb status` and `dpb doctor` cannot end up recommending different things.
const DriftRemedy = "run `dpb tune` (~3 min) to re-measure this line"

// Scope class names as they appear on a ConnEvent.
//
// They are spelled out here rather than imported because observ sits below
// policy in the import graph and policy publishes to observ. The two are pinned
// together mechanically by TestScopeNamesMatchPolicy, which lives in package
// observ_test where importing policy is legal.
const (
	ScopeBypass = "bypass"
	ScopeDirect = "direct"
	ScopeWatch  = "watch"
	ScopeDesync = "desync"
)

// OutcomeOK is the ConnEvent.Outcome value that means the flow completed.
const OutcomeOK = "ok"

// ConnStat is one finished connection, kept per host for display.
//
// It deliberately duplicates a subset of ConnEvent rather than storing the
// event: this type crosses the control socket to `dpb why`, so it must stay
// small and its JSON shape stable.
type ConnStat struct {
	At        time.Time     `json:"at"`
	Spec      string        `json:"spec"`
	Attempts  int           `json:"attempts"`
	OK        bool          `json:"ok"`
	Escalated bool          `json:"escalated"`
	Outcome   string        `json:"outcome"`
	Latency   time.Duration `json:"latency"`
}

// HostStat is one host's activity inside the rolling window.
type HostStat struct {
	Host string `json:"host"`
	// Conns counts every finished connection to this host in the window,
	// including the ones dpb never judged.
	Conns int `json:"conns"`
	// Judged counts the connections dpb was actually in a position to escalate
	// — scope watch or desync. It is the drift rate's unit of evidence.
	Judged    int       `json:"judged"`
	OK        int       `json:"ok"`
	Failed    int       `json:"failed"`
	Escalated int       `json:"escalated"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
}

// Totals are process-lifetime counts. They are never pruned: "how many
// connections has this run served" is a different question from "what is
// happening right now", and answering the first from a rolling window would
// make a quiet minute look like a dead process.
type Totals struct {
	Conns     uint64 `json:"conns"`
	OK        uint64 `json:"ok"`
	Failed    uint64 `json:"failed"`
	Judged    uint64 `json:"judged"`
	Escalated uint64 `json:"escalated"`
	Bypassed  uint64 `json:"bypassed"`
	Direct    uint64 `json:"direct"`
}

// Snapshot is everything `dpb status` reads off the counters at one instant.
type Snapshot struct {
	Now    time.Time     `json:"now"`
	Window time.Duration `json:"window"`
	Totals Totals        `json:"totals"`

	// Hosts and EscalatedHosts are the drift rate's denominator and numerator,
	// exposed so `dpb status` can show why drift did or did not fire rather
	// than only its conclusion.
	Hosts          int     `json:"hosts"`
	EscalatedHosts int     `json:"escalated_hosts"`
	Rate           float64 `json:"rate"`
	// Drift is the most recent DriftEvent, or nil if none has fired.
	Drift *DriftEvent `json:"drift,omitempty"`
	// Top is the hosts seen in the window, most recently active first.
	Top []HostStat `json:"top,omitempty"`
}

// CountersOptions configures a Counters. The zero value is usable and picks
// every default above.
type CountersOptions struct {
	Window        time.Duration
	HostCap       int
	RecentPerHost int
	// MinHosts is how many in-scope hosts must be in the window before a rate
	// means anything. Without it, one escalating host out of one observed host
	// is a 100% drift rate and every first visit to Discord reports that the
	// ISP changed its DPI.
	MinHosts int
	// Rate is the fraction of in-scope hosts that must escalate past their
	// persisted default. Defaults to DefaultDriftRate.
	Rate float64
	// Cooldown is the minimum gap between two DriftEvents. Drift is a standing
	// condition, not an incident, and repeating the report on every connection
	// would bury it.
	Cooldown time.Duration
	Now      func() time.Time
	// OnDrift is called, outside the lock, when drift is newly suspected.
	OnDrift func(DriftEvent)
}

// sample is one connection as the statistics see it. It is separate from
// ConnStat because the display ring is capped at RecentPerHost and the window
// is not: capping the window would silently stop a busy host contributing to
// the rate, which is the direction that hides drift.
type sample struct {
	at        time.Time
	judged    bool
	escalated bool
	ok        bool
}

type hostEntry struct {
	host   string
	recent []ConnStat // newest last, capped at RecentPerHost
	window []sample   // oldest first, pruned to the rolling window
	last   time.Time
}

// Counters is safe for concurrent use. Every front end publishes from a
// per-connection goroutine.
type Counters struct {
	mu    sync.Mutex
	hosts map[string]*hostEntry

	totals    Totals
	lastDrift *DriftEvent

	window   time.Duration
	hostCap  int
	perHost  int
	minHosts int
	rate     float64
	cooldown time.Duration
	now      func() time.Time
	onDrift  func(DriftEvent)
}

// NewCounters builds a Counters from o.
func NewCounters(o CountersOptions) *Counters {
	c := &Counters{
		hosts:    make(map[string]*hostEntry),
		window:   o.Window,
		hostCap:  o.HostCap,
		perHost:  o.RecentPerHost,
		minHosts: o.MinHosts,
		rate:     o.Rate,
		cooldown: o.Cooldown,
		now:      o.Now,
		onDrift:  o.OnDrift,
	}
	if c.window <= 0 {
		c.window = DefaultDriftWindow
	}
	if c.hostCap <= 0 {
		c.hostCap = DefaultCounterHostCap
	}
	if c.perHost <= 0 {
		c.perHost = DefaultRecentPerHost
	}
	if c.minHosts <= 0 {
		c.minHosts = DefaultDriftMinHosts
	}
	if c.rate <= 0 {
		c.rate = DefaultDriftRate
	}
	if c.cooldown <= 0 {
		c.cooldown = DefaultDriftCooldown
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// judged reports whether dpb was in a position to escalate this flow at all.
//
// A ScopeBypass host is never buffered and a ScopeDirect host is relayed
// untouched, so neither can ever escalate. Counting them in the drift
// denominator would mean a user whose browsing is mostly Turkish banks — every
// one of them on the compiled-in bypass list — could never reach the threshold
// no matter how far the DPI drifted.
func judged(scope string) bool {
	return scope == ScopeWatch || scope == ScopeDesync
}

// escalatedPastDefault reports whether this connection is evidence of drift.
//
// docs/PLAN.md's phrase is "escalate past the persisted default". A host whose
// persisted verdict is already a desync cannot do that — it starts on the rung
// it was cached at — so an escalation there says nothing new about the DPI. A
// host on ScopeWatch that escalates is exactly the event drift is made of.
func escalatedPastDefault(ev ConnEvent) bool {
	return ev.Escalated && ev.Scope != ScopeDesync
}

// eventKey is the host an event is filed under. A flow with no name is filed
// under the address it dialled, which is the key policy's verdict store uses
// too, so `dpb why 1.2.3.4` finds the history the cache is keyed by.
func eventKey(ev ConnEvent) string {
	if ev.Host != "" {
		return ev.Host
	}
	return ev.Addr
}

// Observe files one finished connection and, if it has just crossed the drift
// threshold, calls OnDrift.
//
// OnDrift runs after the lock is released: a per-connection goroutine must not
// be able to stall behind whatever the drift handler decides to do.
func (c *Counters) Observe(ev ConnEvent) {
	at := ev.Time
	if at.IsZero() {
		at = c.now()
	}
	inScope := judged(ev.Scope)
	stat := ConnStat{
		At:        at,
		Spec:      ev.Strategy,
		Attempts:  ev.Attempts,
		OK:        ev.Outcome == OutcomeOK,
		Escalated: escalatedPastDefault(ev),
		Outcome:   ev.Outcome,
		Latency:   ev.Duration,
	}

	c.mu.Lock()
	c.totals.Conns++
	if stat.OK {
		c.totals.OK++
	} else {
		c.totals.Failed++
	}
	switch ev.Scope {
	case ScopeBypass:
		c.totals.Bypassed++
	case ScopeDirect:
		c.totals.Direct++
	}
	if inScope {
		c.totals.Judged++
		if stat.Escalated {
			c.totals.Escalated++
		}
	}

	key := eventKey(ev)
	if key == "" {
		// Nothing to file it under. The totals above still counted it, which is
		// the honest outcome: the connection happened, we simply cannot
		// attribute it to a host.
		c.mu.Unlock()
		return
	}

	e := c.hosts[key]
	if e == nil {
		e = &hostEntry{host: key}
		c.hosts[key] = e
	}
	e.last = at
	e.recent = append(e.recent, stat)
	if len(e.recent) > c.perHost {
		e.recent = append(e.recent[:0], e.recent[len(e.recent)-c.perHost:]...)
	}
	e.window = append(e.window, sample{at: at, judged: inScope, escalated: stat.Escalated, ok: stat.OK})

	c.pruneLocked(at)
	c.evictLocked()
	drift := c.evaluateLocked(at)
	c.mu.Unlock()

	if drift != nil && c.onDrift != nil {
		c.onDrift(*drift)
	}
}

// pruneLocked drops window samples older than the rolling window, and forgets
// a host that has none left.
func (c *Counters) pruneLocked(now time.Time) {
	cut := now.Add(-c.window)
	for k, e := range c.hosts {
		i := 0
		for i < len(e.window) && e.window[i].at.Before(cut) {
			i++
		}
		if i > 0 {
			e.window = append(e.window[:0], e.window[i:]...)
		}
		if len(e.window) == 0 {
			// The display ring is only meaningful alongside a live window: a
			// host nothing has connected to for a whole window is not part of
			// "what is happening right now", and keeping it would let a laptop
			// accumulate every host it has ever seen.
			delete(c.hosts, k)
		}
	}
}

// evictLocked enforces the host cap, dropping the least recently seen hosts.
func (c *Counters) evictLocked() {
	for len(c.hosts) > c.hostCap {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.hosts {
			if oldestKey == "" || e.last.Before(oldest) {
				oldestKey, oldest = k, e.last
			}
		}
		delete(c.hosts, oldestKey)
	}
}

// rateLocked is the drift numerator and denominator, counted in DISTINCT HOSTS
// rather than in connections.
//
// Connections would be the wrong unit: a browser opens six sockets to one host,
// so a single drifting site would produce a six-to-one majority over five
// healthy ones. docs/PLAN.md says "more than two thirds of in-scope hosts", and
// hosts is what this counts.
func (c *Counters) rateLocked() (hosts, escalated int, rate float64) {
	for _, e := range c.hosts {
		var sawJudged, sawEscalation bool
		for _, s := range e.window {
			if !s.judged {
				continue
			}
			sawJudged = true
			if s.escalated {
				sawEscalation = true
				break
			}
		}
		if !sawJudged {
			continue
		}
		hosts++
		if sawEscalation {
			escalated++
		}
	}
	if hosts > 0 {
		rate = float64(escalated) / float64(hosts)
	}
	return hosts, escalated, rate
}

// evaluateLocked fires a DriftEvent if the threshold has been crossed and the
// cooldown has elapsed. It returns the event to publish, or nil.
func (c *Counters) evaluateLocked(now time.Time) *DriftEvent {
	hosts, escalated, rate := c.rateLocked()
	if hosts < c.minHosts || rate <= c.rate {
		return nil
	}
	if c.lastDrift != nil && now.Sub(c.lastDrift.Time) < c.cooldown {
		return nil
	}
	ev := DriftEvent{
		Time:      now,
		Window:    c.window,
		Hosts:     hosts,
		Escalated: escalated,
		Rate:      rate,
		Suspected: "your ISP's DPI likely changed: most hosts dpb is watching now need " +
			"a desync they did not need before",
		Remedy: DriftRemedy,
	}
	c.lastDrift = &ev
	return &ev
}

// Recent returns the last few outcomes for one host, oldest first. It is what
// `dpb why` prints under the verdict, so a user can see the decision and its
// consequences side by side.
func (c *Counters) Recent(host string) []ConnStat {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.hosts[host]
	if e == nil {
		return nil
	}
	return append([]ConnStat(nil), e.recent...)
}

// Snapshot is the whole picture at one instant.
func (c *Counters) Snapshot() Snapshot {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)

	hosts, escalated, rate := c.rateLocked()
	s := Snapshot{
		Now:            now,
		Window:         c.window,
		Totals:         c.totals,
		Hosts:          hosts,
		EscalatedHosts: escalated,
		Rate:           rate,
		Top:            c.topLocked(),
	}
	if c.lastDrift != nil {
		d := *c.lastDrift
		s.Drift = &d
	}
	return s
}

// topLocked builds the per-host table, most recently active first. Ties break
// on the host name so two runs of `dpb status` on a quiet machine agree.
func (c *Counters) topLocked() []HostStat {
	out := make([]HostStat, 0, len(c.hosts))
	for _, e := range c.hosts {
		st := HostStat{Host: e.host, Last: e.last, Conns: len(e.window)}
		for _, s := range e.window {
			if st.First.IsZero() || s.at.Before(st.First) {
				st.First = s.at
			}
			if s.ok {
				st.OK++
			} else {
				st.Failed++
			}
			if s.judged {
				st.Judged++
				if s.escalated {
					st.Escalated++
				}
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// Drift returns the most recent drift report, or nil.
func (c *Counters) Drift() *DriftEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastDrift == nil {
		return nil
	}
	d := *c.lastDrift
	return &d
}

// Hosts is how many hosts are currently tracked. It exists so a test can assert
// the LRU cap actually evicts rather than inferring it from memory use.
func (c *Counters) Hosts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hosts)
}
