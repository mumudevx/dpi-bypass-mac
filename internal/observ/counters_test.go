package observ

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// clock is a hand-cranked time source. Drift is a statement about a rolling
// window, and a test that depended on wall time would either be slow or flaky.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func conn(at time.Time, host, scope string, escalated, ok bool) ConnEvent {
	outcome := OutcomeOK
	if !ok {
		outcome = "reset"
	}
	return ConnEvent{
		Time: at, Host: host, Scope: scope, Escalated: escalated,
		Outcome: outcome, Attempts: 1, Strategy: "tlsfrag:pos=snimid",
	}
}

func TestCountersTotals(t *testing.T) {
	c := newClock()
	ct := NewCounters(CountersOptions{Now: c.now})

	ct.Observe(conn(c.now(), "discord.com", ScopeWatch, true, true))
	ct.Observe(conn(c.now(), "www.isbank.com.tr", ScopeBypass, false, true))
	ct.Observe(conn(c.now(), "example.com", ScopeDirect, false, false))

	tot := ct.Snapshot().Totals
	if tot.Conns != 3 || tot.OK != 2 || tot.Failed != 1 {
		t.Errorf("totals = %+v", tot)
	}
	if tot.Bypassed != 1 || tot.Direct != 1 {
		t.Errorf("scope totals = %+v", tot)
	}
	if tot.Judged != 1 || tot.Escalated != 1 {
		t.Errorf("judged/escalated = %d/%d, want 1/1 (only the watched flow counts)",
			tot.Judged, tot.Escalated)
	}
}

// Drift is counted in DISTINCT HOSTS, not in connections. A browser opens six
// sockets to one host, so counting connections would let a single drifting site
// outvote five healthy ones.
func TestDriftCountsHostsNotConnections(t *testing.T) {
	c := newClock()
	var fired []DriftEvent
	ct := NewCounters(CountersOptions{
		Now:      c.now,
		MinHosts: 3,
		OnDrift:  func(e DriftEvent) { fired = append(fired, e) },
	})

	// One host escalating six times, two healthy hosts. Per connection that is
	// 6/8 — over the two-thirds line. Per host it is 1/3, which is not.
	for range 6 {
		ct.Observe(conn(c.now(), "discord.com", ScopeWatch, true, true))
		c.advance(time.Second)
	}
	ct.Observe(conn(c.now(), "cloudflare.com", ScopeWatch, false, true))
	ct.Observe(conn(c.now(), "example.com", ScopeWatch, false, true))

	if len(fired) != 0 {
		t.Fatalf("drift fired on one escalating host out of three: %+v", fired)
	}
	s := ct.Snapshot()
	if s.Hosts != 3 || s.EscalatedHosts != 1 {
		t.Fatalf("hosts=%d escalated=%d, want 3 and 1", s.Hosts, s.EscalatedHosts)
	}
}

func TestDriftFiresPastTheThreshold(t *testing.T) {
	c := newClock()
	var fired []DriftEvent
	ct := NewCounters(CountersOptions{
		Now:      c.now,
		MinHosts: 3,
		OnDrift:  func(e DriftEvent) { fired = append(fired, e) },
	})

	for i := range 3 {
		ct.Observe(conn(c.now(), fmt.Sprintf("host%d.example", i), ScopeWatch, true, true))
		c.advance(time.Second)
	}
	if len(fired) != 1 {
		t.Fatalf("drift fired %d time(s), want 1 once every in-scope host escalated", len(fired))
	}
	ev := fired[0]
	if ev.Hosts != 3 || ev.Escalated != 3 || ev.Rate != 1 {
		t.Errorf("event = %+v", ev)
	}
	if ev.Remedy != DriftRemedy {
		t.Errorf("remedy = %q, want the one every surface prints", ev.Remedy)
	}
	if ct.Drift() == nil {
		t.Error("Drift() returned nil after an event fired")
	}
}

// A host whose persisted verdict is already a desync starts on the rung it was
// cached at and cannot escalate PAST that default. Counting it would make the
// steady state on a censored line look like a change.
func TestDriftIgnoresEscalationOnAnAlreadyDesyncedHost(t *testing.T) {
	c := newClock()
	var fired []DriftEvent
	ct := NewCounters(CountersOptions{
		Now: c.now, MinHosts: 3, OnDrift: func(e DriftEvent) { fired = append(fired, e) },
	})
	for i := range 4 {
		ct.Observe(conn(c.now(), fmt.Sprintf("host%d.example", i), ScopeDesync, true, true))
		c.advance(time.Second)
	}
	if len(fired) != 0 {
		t.Fatalf("drift fired for hosts that were already pinned to a desync: %+v", fired)
	}
	if s := ct.Snapshot(); s.EscalatedHosts != 0 {
		t.Errorf("escalated hosts = %d, want 0", s.EscalatedHosts)
	}
}

// Bypassed and direct hosts are never buffered and never escalated, so they
// cannot be part of the denominator. A user whose browsing is mostly Turkish
// banks — every one on the compiled-in bypass list — must still be able to
// reach the threshold.
func TestDriftDenominatorExcludesOutOfScopeHosts(t *testing.T) {
	c := newClock()
	var fired []DriftEvent
	ct := NewCounters(CountersOptions{
		Now: c.now, MinHosts: 3, OnDrift: func(e DriftEvent) { fired = append(fired, e) },
	})

	for i := range 10 {
		ct.Observe(conn(c.now(), fmt.Sprintf("bank%d.com.tr", i), ScopeBypass, false, true))
		c.advance(time.Second)
	}
	for i := range 3 {
		ct.Observe(conn(c.now(), fmt.Sprintf("host%d.example", i), ScopeWatch, true, true))
		c.advance(time.Second)
	}
	if len(fired) != 1 {
		t.Fatalf("drift fired %d time(s); ten bypassed hosts must not dilute three escalating ones", len(fired))
	}
}

func TestDriftMinHostsSuppressesASingleSample(t *testing.T) {
	c := newClock()
	var fired []DriftEvent
	ct := NewCounters(CountersOptions{
		Now: c.now, MinHosts: 6, OnDrift: func(e DriftEvent) { fired = append(fired, e) },
	})
	// The very first visit to Discord on a censored line escalates. One host out
	// of one is a 100% rate, and reporting "your ISP changed its DPI" there
	// would make the warning worthless.
	ct.Observe(conn(c.now(), "discord.com", ScopeWatch, true, true))
	if len(fired) != 0 {
		t.Fatalf("drift fired on a single host: %+v", fired)
	}
}

func TestDriftCooldown(t *testing.T) {
	c := newClock()
	var fired []DriftEvent
	ct := NewCounters(CountersOptions{
		Now: c.now, MinHosts: 3, Cooldown: time.Hour,
		OnDrift: func(e DriftEvent) { fired = append(fired, e) },
	})
	observe := func() {
		for i := range 3 {
			ct.Observe(conn(c.now(), fmt.Sprintf("host%d.example", i), ScopeWatch, true, true))
		}
	}
	observe()
	if len(fired) != 1 {
		t.Fatalf("first pass fired %d times", len(fired))
	}
	c.advance(30 * time.Minute)
	observe()
	if len(fired) != 1 {
		t.Fatalf("drift re-fired inside the cooldown: %d events", len(fired))
	}
	c.advance(31 * time.Minute)
	observe()
	if len(fired) != 2 {
		t.Fatalf("drift did not re-fire after the cooldown: %d events", len(fired))
	}
}

// Samples older than the window stop counting, and a host with nothing left in
// the window is forgotten entirely.
func TestWindowExpiry(t *testing.T) {
	c := newClock()
	ct := NewCounters(CountersOptions{Now: c.now, Window: 10 * time.Minute, MinHosts: 3})
	for i := range 3 {
		ct.Observe(conn(c.now(), fmt.Sprintf("host%d.example", i), ScopeWatch, true, true))
	}
	if s := ct.Snapshot(); s.Hosts != 3 {
		t.Fatalf("hosts = %d before expiry", s.Hosts)
	}
	c.advance(11 * time.Minute)
	s := ct.Snapshot()
	if s.Hosts != 0 {
		t.Fatalf("hosts = %d after the window elapsed, want 0", s.Hosts)
	}
	if s.Totals.Conns != 3 {
		t.Errorf("totals were pruned too: %+v — lifetime counts must not roll off", s.Totals)
	}
}

func TestHostCapEvicts(t *testing.T) {
	c := newClock()
	ct := NewCounters(CountersOptions{Now: c.now, HostCap: 4})
	for i := range 20 {
		ct.Observe(conn(c.now(), fmt.Sprintf("host%d.example", i), ScopeWatch, false, true))
		c.advance(time.Second)
	}
	if got := ct.Hosts(); got != 4 {
		t.Fatalf("tracked %d hosts, want the cap of 4", got)
	}
	// The most recent host survives; the oldest does not.
	if len(ct.Recent("host19.example")) == 0 {
		t.Error("the most recently seen host was evicted")
	}
	if len(ct.Recent("host0.example")) != 0 {
		t.Error("the least recently seen host survived the cap")
	}
}

func TestRecentIsCappedAndOrdered(t *testing.T) {
	c := newClock()
	ct := NewCounters(CountersOptions{Now: c.now, RecentPerHost: 3})
	for i := range 6 {
		ev := conn(c.now(), "discord.com", ScopeWatch, false, true)
		ev.Attempts = i
		ct.Observe(ev)
		c.advance(time.Second)
	}
	got := ct.Recent("discord.com")
	if len(got) != 3 {
		t.Fatalf("Recent returned %d entries, want the cap of 3", len(got))
	}
	if got[0].Attempts != 3 || got[2].Attempts != 5 {
		t.Fatalf("Recent = %v, want the last three in order", []int{got[0].Attempts, got[1].Attempts, got[2].Attempts})
	}
}

// An unnamed flow is filed under the address it dialled, which is the key the
// verdict store uses for it too.
func TestUnnamedFlowIsFiledUnderItsAddress(t *testing.T) {
	c := newClock()
	ct := NewCounters(CountersOptions{Now: c.now})
	ct.Observe(ConnEvent{Time: c.now(), Addr: "1.2.3.4:443", Scope: ScopeWatch, Outcome: OutcomeOK})
	if len(ct.Recent("1.2.3.4:443")) != 1 {
		t.Fatal("an unnamed flow was not filed under its address")
	}
}

// An event with neither a name nor an address still counts in the totals: the
// connection happened, we simply cannot attribute it.
func TestEventWithNoKeyStillCounts(t *testing.T) {
	ct := NewCounters(CountersOptions{Now: newClock().now})
	ct.Observe(ConnEvent{Scope: ScopeWatch, Outcome: OutcomeOK})
	if got := ct.Snapshot().Totals.Conns; got != 1 {
		t.Fatalf("totals.Conns = %d, want 1", got)
	}
	if ct.Hosts() != 0 {
		t.Fatalf("an unattributable event created a host entry")
	}
}

func TestSnapshotTopIsOrdered(t *testing.T) {
	c := newClock()
	ct := NewCounters(CountersOptions{Now: c.now})
	ct.Observe(conn(c.now(), "old.example", ScopeWatch, false, true))
	c.advance(time.Minute)
	ct.Observe(conn(c.now(), "new.example", ScopeWatch, true, false))

	top := ct.Snapshot().Top
	if len(top) != 2 || top[0].Host != "new.example" {
		t.Fatalf("top = %+v, want the most recently active host first", top)
	}
	if top[0].Failed != 1 || top[0].Escalated != 1 || top[0].Judged != 1 {
		t.Errorf("top[0] = %+v", top[0])
	}
}

func TestCountersAreConcurrencySafe(t *testing.T) {
	ct := NewCounters(CountersOptions{})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 50 {
				ct.Observe(conn(time.Now(), fmt.Sprintf("host%d.example", (i*50+j)%17),
					ScopeWatch, j%2 == 0, j%3 == 0))
				_ = ct.Snapshot()
				_ = ct.Recent("host1.example")
			}
		}(i)
	}
	wg.Wait()
	if got := ct.Snapshot().Totals.Conns; got != 400 {
		t.Fatalf("totals.Conns = %d, want 400", got)
	}
}

func TestCountersDefaults(t *testing.T) {
	ct := NewCounters(CountersOptions{})
	if ct.window != DefaultDriftWindow || ct.hostCap != DefaultCounterHostCap ||
		ct.perHost != DefaultRecentPerHost || ct.minHosts != DefaultDriftMinHosts ||
		ct.rate != DefaultDriftRate || ct.cooldown != DefaultDriftCooldown {
		t.Fatalf("the zero options did not pick every default: window=%v hostCap=%d "+
			"perHost=%d minHosts=%d rate=%v cooldown=%v",
			ct.window, ct.hostCap, ct.perHost, ct.minHosts, ct.rate, ct.cooldown)
	}
	if ct.now == nil {
		t.Fatal("the zero options left a nil clock")
	}
	if ct.Drift() != nil {
		t.Fatal("a fresh Counters reported drift")
	}
	if got := ct.Recent("nobody.example"); got != nil {
		t.Fatalf("Recent on an unknown host = %v", got)
	}
}
