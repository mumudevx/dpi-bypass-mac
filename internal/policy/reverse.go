package policy

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// ReverseMap remembers which name we answered with which addresses, so a TUN
// flow to a bare IP can be named before its ClientHello is even read.
//
// This is what replaces the fake-IP layer other designs use. Fake IPs buy an
// exclusion guarantee at the cost of a 198.18.0.0/15 collision surface, broken
// IP pinning and a browser-DoH bypass; under default-direct an unnamed flow is
// simply judged by its own ClientHello and is exactly as safe as a named one,
// so a best-effort map is all that is needed.
type ReverseMap interface {
	Learn(name string, ips []netip.Addr, ttl time.Duration)
	Lookup(ip netip.Addr) (string, bool)
}

const (
	// defaultReverseMax matches the verdict cache: a browsing session resolves
	// far fewer names than this.
	defaultReverseMax = 4096
	// minReverseTTL floors the retention of an answer. CDNs hand out TTLs of a
	// few seconds, and the connection that follows our own DNS reply arrives
	// milliseconds later but may live for minutes; expiring the name out from
	// under it would lose the only naming we have for a TUN flow.
	minReverseTTL = 60 * time.Second
	// maxReverseTTL bounds a hostile or careless TTL so one answer cannot pin
	// an address to a stale name for a week.
	maxReverseTTL = time.Hour
)

type reverseEntry struct {
	addr    netip.Addr
	name    string
	expires time.Time
	elem    *list.Element
}

type reverseMap struct {
	mu    sync.Mutex
	max   int
	now   func() time.Time
	byIP  map[netip.Addr]*reverseEntry
	order *list.List // front = most recently learned or looked up
}

var _ ReverseMap = (*reverseMap)(nil)

// NewReverseMap returns a map holding at most max addresses (<=0 means the
// default).
func NewReverseMap(max int) ReverseMap { return NewReverseMapClock(max, nil) }

// NewReverseMapClock is the injectable-clock constructor tests use; expiry is
// otherwise untestable without sleeping.
func NewReverseMapClock(max int, now func() time.Time) ReverseMap {
	if max <= 0 {
		max = defaultReverseMax
	}
	if now == nil {
		now = time.Now
	}
	return &reverseMap{
		max:   max,
		now:   now,
		byIP:  make(map[netip.Addr]*reverseEntry, max),
		order: list.New(),
	}
}

// Learn records that name resolved to ips.
//
// On collision the newest name wins. Many names share one CDN address, and the
// flow that follows a DNS answer is overwhelmingly the flow for the name we
// just answered — so recency is the best available guess, and a wrong guess
// only costs the accuracy of a scope decision that ScopeWatch would have made
// safely anyway.
func (m *reverseMap) Learn(name string, ips []netip.Addr, ttl time.Duration) {
	n := Normalize(name)
	if n == "" || len(ips) == 0 {
		return
	}
	switch {
	case ttl < minReverseTTL:
		ttl = minReverseTTL
	case ttl > maxReverseTTL:
		ttl = maxReverseTTL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp := m.now().Add(ttl)
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		a := canonAddr(ip)
		if e, ok := m.byIP[a]; ok {
			e.name, e.expires = n, exp
			m.order.MoveToFront(e.elem)
			continue
		}
		e := &reverseEntry{addr: a, name: n, expires: exp}
		e.elem = m.order.PushFront(e)
		m.byIP[a] = e
	}
	for m.order.Len() > m.max {
		back := m.order.Back()
		if back == nil {
			break
		}
		old := back.Value.(*reverseEntry)
		m.order.Remove(back)
		delete(m.byIP, old.addr)
	}
}

// Lookup returns the most recently learned name for ip.
func (m *reverseMap) Lookup(ip netip.Addr) (string, bool) {
	if !ip.IsValid() {
		return "", false
	}
	a := canonAddr(ip)
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byIP[a]
	if !ok {
		return "", false
	}
	if !m.now().Before(e.expires) {
		m.order.Remove(e.elem)
		delete(m.byIP, a)
		return "", false
	}
	m.order.MoveToFront(e.elem)
	return e.name, true
}

// Len reports how many addresses are mapped, expired entries included. It
// exists for tests and for `dpb status`.
func (m *reverseMap) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.order.Len()
}
