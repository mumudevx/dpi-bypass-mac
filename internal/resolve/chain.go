package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
)

// Resolver is one transport in the chain.
type Resolver interface {
	Label() string
	Transport() string // "doh" | "dot" | "udp" | "udp-alt"
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

// DialFunc is the uplink-bound, desyncing dial path DoH and DoT are given, so
// the resolver's own ClientHello is protected by the same ladder as every other
// connection and the query never re-enters the tunnel.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ReverseMap is the IP→name map the front ends consult to name a flow whose
// destination we ourselves answered for.
//
// It is declared here structurally rather than imported from internal/policy so
// this package's dependency set stays at "the pure ones". A policy.ReverseMap
// satisfies it and can be assigned to Options.Reverse unchanged.
type ReverseMap interface {
	Learn(name string, ips []netip.Addr, ttl time.Duration)
	Lookup(ip netip.Addr) (string, bool)
}

// Health is the last observed state of one resolver.
type Health struct {
	Label   string
	OK      bool
	Latency time.Duration
	Signal  Signal
	Err     error
}

// Options configures a Chain. Only Resolvers is required.
type Options struct {
	Resolvers []Resolver
	AAAA      AAAAMode
	Detector  Detector
	Reverse   ReverseMap
	CacheTTL  time.Duration
	NegTTL    time.Duration
	Logf      func(string, ...any)

	// PerTry bounds one resolver attempt. It has to exist: MEASUREMENTS.md §2
	// measures the censorship as a per-QNAME *drop*, so the failure mode of the
	// first rung is silence, and a chain with no per-rung deadline never
	// advances past it.
	PerTry time.Duration
	// V4Path reports whether a usable IPv4 path exists; nil means look at the
	// interface addresses.
	V4Path func() bool
	// Now is the clock, for tests.
	Now func() time.Time
}

const (
	defaultPerTry   = 4 * time.Second
	defaultCacheTTL = 5 * time.Minute
	defaultNegTTL   = 30 * time.Second
	// cacheMax bounds the answer cache. Sizing choice, stated as such.
	cacheMax = 4096
)

var (
	// ErrNoResolvers means the chain was built empty, which is a configuration
	// bug, not a network condition.
	ErrNoResolvers = errors.New("resolve: chain has no resolvers")
	// ErrChainExhausted means every resolver failed, was dropped, or answered
	// with censorship.
	ErrChainExhausted = errors.New("resolve: every resolver in the chain failed")
	// ErrNoAddress means the name resolved with no A or AAAA record.
	ErrNoAddress = errors.New("resolve: name has no address record")
)

type cacheKey struct {
	name  string
	qtype uint16
	class uint16
}

type cacheEntry struct {
	msg []byte // stored with the transaction ID zeroed
	exp time.Time
}

// Chain is the single DNS funnel. Every name this process turns into an address
// goes through it, and nothing in it can reach Go's own resolver.
type Chain struct {
	resolvers []Resolver
	det       Detector
	rev       ReverseMap
	aaaa      *aaaaPolicy
	cacheTTL  time.Duration
	negTTL    time.Duration
	perTry    time.Duration
	logf      func(string, ...any)
	now       func() time.Time

	mu     sync.Mutex
	cache  map[cacheKey]cacheEntry
	health map[string]Health

	natMu   sync.Mutex
	natSeen time.Time
	natLast NAT64
}

// NewChain builds a Chain. It never returns nil: a chain with no resolvers is
// still a chain, and it answers SERVFAIL rather than panicking inside a
// connection goroutine.
func NewChain(o Options) *Chain {
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	det := o.Detector
	if det == nil {
		det = NewDetector(nil, nil)
	}
	c := &Chain{
		resolvers: append([]Resolver(nil), o.Resolvers...),
		det:       det,
		rev:       o.Reverse,
		cacheTTL:  or(o.CacheTTL, defaultCacheTTL),
		negTTL:    or(o.NegTTL, defaultNegTTL),
		perTry:    or(o.PerTry, defaultPerTry),
		logf:      logf,
		now:       now,
		cache:     make(map[cacheKey]cacheEntry),
		health:    make(map[string]Health),
	}
	v4 := o.V4Path
	if v4 == nil {
		v4 = hasGlobalIPv4
	}
	c.aaaa = &aaaaPolicy{mode: o.AAAA, v4Path: v4, nat64: c.nat64Cached}
	return c
}

func or(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

// Labels lists the resolvers in chain order.
func (c *Chain) Labels() []string {
	out := make([]string, 0, len(c.resolvers))
	for _, r := range c.resolvers {
		out = append(out, r.Label())
	}
	return out
}

// Health reports the last observed state of every resolver, in chain order. A
// resolver that has never been tried reports OK=false with a nil error, which
// `dpb dns check` renders as "untried" rather than "broken".
func (c *Chain) Health() []Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Health, 0, len(c.resolvers))
	for _, r := range c.resolvers {
		h, ok := c.health[r.Label()]
		if !ok {
			h = Health{Label: r.Label()}
		}
		out = append(out, h)
	}
	return out
}

func (c *Chain) setHealth(h Health) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health[h.Label] = h
}

// Exchange is the single DNS funnel.
//
// It rejects plaintext TCP structurally (no resolver here can open one), drops
// sinkhole and uniqueness-flagged answers and advances the chain rather than
// treating them as a fallback, applies the AAAA policy, records the reverse
// mapping, and synthesises a well-formed SERVFAIL carrying the caller's own ID
// and question on chain exhaustion instead of closing the session.
//
// The returned message is always usable even when the error is non-nil: the
// caller writing bytes back to a stub wants the SERVFAIL, the caller deciding
// whether the network works wants the error.
func (c *Chain) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	q, err := FirstQuestion(query)
	if err != nil {
		return SynthRcode(query, dns.RcodeFormatError), fmt.Errorf("resolve: unusable query: %w", err)
	}
	name := normName(q.Name)

	if q.Type == dns.TypeAAAA {
		if allow, why := c.aaaa.allow(ctx); !allow {
			c.logf("resolve: suppressing AAAA for %s (%s); answering NOERROR with an empty answer, never NXDOMAIN", name, why)
			return SynthEmpty(query), nil
		}
	}

	key := cacheKey{name: name, qtype: q.Type, class: q.Class}
	if msg, ok := c.cacheGet(key); ok {
		return c.withCallerID(query, msg), nil
	}

	answer, err := c.exchangeDirect(ctx, query)
	if err != nil {
		return SynthRcode(query, dns.RcodeServerFailure), err
	}

	m, perr := unpack(answer)
	if perr == nil {
		addrs := answerAddrs(m)
		ttl := minTTL(m)
		if len(addrs) > 0 && c.rev != nil {
			// The reverse mapping is recorded BEFORE the reply goes out so the
			// TCP flow that follows this answer already knows the hostname.
			c.rev.Learn(name, addrs, c.cacheableFor(ttl))
		}
		c.cachePut(key, answer, m, ttl)
	}
	return answer, nil
}

// cacheableFor clamps an upstream TTL into the window we are willing to trust.
func (c *Chain) cacheableFor(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return c.negTTL
	}
	if ttl > c.cacheTTL {
		return c.cacheTTL
	}
	return ttl
}

// exchangeDirect walks the chain. It is the poison-checking, TC-handling core
// shared by Exchange and by the NAT64 probe, which must not be filtered by the
// AAAA policy it feeds.
func (c *Chain) exchangeDirect(ctx context.Context, query []byte) ([]byte, error) {
	if len(c.resolvers) == 0 {
		return nil, ErrNoResolvers
	}
	q, err := FirstQuestion(query)
	if err != nil {
		return nil, fmt.Errorf("resolve: unusable query: %w", err)
	}
	name := normName(q.Name)

	var (
		errs      []error
		truncated []byte
		sawTrunc  bool
	)
	for _, r := range c.resolvers {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		// Once a plaintext resolver has truncated, every other plaintext
		// resolver will truncate identically. The RFC answer is "retry over
		// TCP"; MEASUREMENTS.md §2 measures TCP/53 as connection-reset at every
		// port on this ISP, so the only correct move is to re-ask an encrypted
		// resolver, and to skip the ones that cannot help.
		if sawTrunc && isPlaintext(r) {
			continue
		}

		start := c.now()
		try, cancel := context.WithTimeout(ctx, c.perTry)
		ans, err := r.Exchange(try, query)
		cancel()
		latency := c.now().Sub(start)

		if err != nil {
			c.setHealth(Health{Label: r.Label(), Latency: latency, Err: err})
			errs = append(errs, fmt.Errorf("%s: %w", r.Label(), err))
			c.logf("resolve: %s failed %s after %s: %v", r.Label(), q, latency.Round(time.Millisecond), err)
			continue
		}

		addrs := AnswerAddrs(ans)
		c.det.Learn(name, addrs)
		sig := c.det.Check(name, addrs)
		if sig.Poisoned {
			c.notePoison(name, addrs, sig)
			c.setHealth(Health{Label: r.Label(), Latency: latency, Signal: sig,
				Err: fmt.Errorf("poisoned answer: %s", sig.Detail)})
			errs = append(errs, fmt.Errorf("%s: poisoned answer: %s", r.Label(), sig.Detail))
			c.logf("resolve: %s returned a poisoned answer for %s (%s); advancing the chain",
				r.Label(), name, sig.Detail)
			continue
		}

		if Truncated(ans) && isPlaintext(r) {
			sawTrunc = true
			truncated = ans
			c.setHealth(Health{Label: r.Label(), Latency: latency, Signal: sig,
				Err: errors.New("answer truncated; re-asking an encrypted resolver, never TCP")})
			c.logf("resolve: %s truncated %s; re-asking an encrypted resolver (TCP/53 is never attempted)", r.Label(), q)
			continue
		}

		c.setHealth(Health{Label: r.Label(), OK: true, Latency: latency, Signal: sig})
		return ans, nil
	}

	if truncated != nil {
		// Every encrypted resolver is gone too. Handing the stub the truncated
		// answer is still better than silence: it carries the header, the
		// question and whatever fit, and our own local server answers the
		// stub's TCP retry in-process without the query leaving the machine.
		c.logf("resolve: %s: only a truncated answer is available; returning it rather than falling back to TCP", q)
		return truncated, nil
	}
	return nil, fmt.Errorf("%w for %s: %w", ErrChainExhausted, q, errors.Join(errs...))
}

// notePoison feeds the AAAA policy the positive evidence it waits for.
func (c *Chain) notePoison(name string, addrs []netip.Addr, sig Signal) {
	if !sig.Sinkhole {
		return
	}
	for _, a := range addrs {
		if a.Is6() && !a.Is4In6() {
			c.aaaa.noteV6Poison(fmt.Sprintf("an IPv6 answer for %s was the sinkhole %s", name, a))
			return
		}
	}
}

func isPlaintext(r Resolver) bool {
	t := r.Transport()
	return t == "udp" || t == "udp-alt"
}

// nat64Cached memoises the RFC 7050 probe so the AAAA policy costs one query
// per nat64TTL rather than one per name.
func (c *Chain) nat64Cached(ctx context.Context) NAT64 {
	c.natMu.Lock()
	defer c.natMu.Unlock()
	if !c.natSeen.IsZero() && c.now().Sub(c.natSeen) < nat64TTL {
		return c.natLast
	}
	c.natLast = c.detectNAT64(ctx)
	c.natSeen = c.now()
	return c.natLast
}

func (c *Chain) cacheGet(k cacheKey) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[k]
	if !ok {
		return nil, false
	}
	if c.now().After(e.exp) {
		delete(c.cache, k)
		return nil, false
	}
	return e.msg, true
}

// cachePut stores positive and negative answers alike. A negative answer is
// cached for a much shorter window: NXDOMAIN and SERVFAIL here are as likely to
// be a censored transport as a real absence, and the chain should get another
// chance soon.
func (c *Chain) cachePut(k cacheKey, msg []byte, m *dns.Msg, ttl time.Duration) {
	// A truncated answer is a transport artefact, not a result. Caching it
	// would hand every later caller a TC=1 they can only act on by retrying
	// over TCP, which MEASUREMENTS.md §2 measures as reset at every port.
	if m.Truncated {
		return
	}
	var life time.Duration
	switch {
	case m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0:
		life = c.cacheableFor(ttl)
	default:
		life = c.negTTL
	}
	if life <= 0 {
		return
	}
	stored := make([]byte, len(msg))
	copy(stored, msg)
	_ = SetMsgID(stored, 0)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= cacheMax {
		c.evictLocked()
	}
	c.cache[k] = cacheEntry{msg: stored, exp: c.now().Add(life)}
}

// evictLocked drops expired entries first and, if that freed nothing, one
// arbitrary entry so the map cannot grow without bound.
func (c *Chain) evictLocked() {
	now := c.now()
	freed := 0
	for k, e := range c.cache {
		if now.After(e.exp) {
			delete(c.cache, k)
			freed++
		}
	}
	if freed > 0 {
		return
	}
	for k := range c.cache {
		delete(c.cache, k)
		return
	}
}

// withCallerID returns a copy of a cached answer carrying the caller's ID.
func (c *Chain) withCallerID(query, cached []byte) []byte {
	out := make([]byte, len(cached))
	copy(out, cached)
	if id, err := MsgID(query); err == nil {
		_ = SetMsgID(out, id)
	}
	return out
}

// Resolve turns a host into addresses.
//
// An IP literal is returned unchanged and never queried: the front ends pass
// whatever the client asked for, and asking a resolver about "1.1.1.1" is both
// pointless and, on a censored network, a way to get an answer that is not
// 1.1.1.1.
func (c *Chain) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	h := strings.TrimSpace(host)
	h = strings.TrimSuffix(h, ".")
	h = strings.Trim(h, "[]")
	if h == "" {
		return nil, errors.New("resolve: empty host")
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	h = strings.ToLower(h)

	type result struct {
		addrs []netip.Addr
		err   error
	}
	var (
		v4, v6 result
		wg     sync.WaitGroup
	)
	// A and AAAA go out in parallel: the chain's rungs are sequential per
	// query, and serialising the two families would double the worst case on
	// exactly the networks where the first rungs are being dropped.
	for _, spec := range []struct {
		qtype uint16
		out   *result
		name  string
	}{
		{dns.TypeA, &v4, "a"},
		{dns.TypeAAAA, &v6, "aaaa"},
	} {
		wg.Add(1)
		flow.Safe("resolve.chain."+spec.name, c.logf, func() {
			defer wg.Done()
			spec.out.addrs, spec.out.err = c.lookup(ctx, h, spec.qtype)
		})
	}
	wg.Wait()

	// IPv4 first. DOSSIER GT19 records a BTK-registered IPv6 sinkhole range,
	// so when both families answer, the family this tool has measured end to
	// end is the one a caller taking addrs[0] should get.
	addrs := append(append([]netip.Addr(nil), v4.addrs...), v6.addrs...)
	if len(addrs) > 0 {
		return addrs, nil
	}
	switch {
	case v4.err != nil && v6.err != nil:
		return nil, fmt.Errorf("resolve: %s: %w", h, errors.Join(v4.err, v6.err))
	case v4.err != nil:
		return nil, fmt.Errorf("resolve: %s: %w", h, v4.err)
	case v6.err != nil:
		return nil, fmt.Errorf("resolve: %s: %w", h, v6.err)
	default:
		return nil, fmt.Errorf("%w: %s", ErrNoAddress, h)
	}
}

func (c *Chain) lookup(ctx context.Context, host string, qtype uint16) ([]netip.Addr, error) {
	q, err := NewQuery(host, qtype)
	if err != nil {
		return nil, err
	}
	ans, err := c.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if rc := Rcode(ans); rc != dns.RcodeSuccess {
		return nil, fmt.Errorf("resolve: %s %s: rcode %s", host, dns.TypeToString[qtype], dns.RcodeToString[rc])
	}
	return AnswerAddrs(ans), nil
}
