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

	poisonMu   sync.Mutex
	poisonSeen map[netip.Addr]bool
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

	st := &walkState{}
	if ans := c.walk(ctx, query, name, q, st, walkAll); ans != nil {
		return ans, nil
	}

	// A plaintext rung truncated. The RFC answer is "retry over TCP" and
	// MEASUREMENTS.md §2 measures plaintext TCP DNS as connection-reset at
	// every port on this ISP, so the only move left is to re-ask an encrypted
	// rung. Continuing forward cannot reach one: DefaultEndpoints puts all
	// three encrypted rungs BEFORE both plaintext rungs, so by the time a
	// plaintext rung truncates every encrypted rung is already behind us.
	// Restart the walk at the first encrypted rung instead. The second pass is
	// bounded by whatever is left of the caller's deadline, so it costs
	// nothing when there is nothing left to spend.
	if st.truncated != nil && c.hasEncrypted() {
		c.logf("resolve: %s: a plaintext rung truncated; restarting the walk at the first encrypted rung (TCP/53 is never attempted)", q)
		if ans := c.walk(ctx, query, name, q, st, walkEncryptedOnly); ans != nil {
			return ans, nil
		}
	}

	if st.truncated != nil {
		// Every encrypted resolver is gone too. Handing the stub the truncated
		// answer is still better than silence: it carries the header, the
		// question and whatever fit. It is never handed back over the TCP
		// listener, where TC is meaningless — see Server.serveTCPConn.
		c.logf("resolve: %s: only a truncated answer is available; returning it rather than falling back to TCP", q)
		return st.truncated, nil
	}
	return nil, fmt.Errorf("%w for %s: %w", ErrChainExhausted, q, errors.Join(st.errs...))
}

// walkState carries what one pass over the chain learned into the next.
type walkState struct {
	errs      []error
	truncated []byte
	sawTrunc  bool
}

// walkMode selects which rungs a pass is allowed to try.
type walkMode int

const (
	// walkAll is the ordinary pass: every rung in chain order, minus the
	// plaintext rungs skipped once one of them has truncated.
	walkAll walkMode = iota
	// walkEncryptedOnly is the truncation retry: encrypted rungs only, from
	// the front of the chain.
	walkEncryptedOnly
)

// rungBudget bounds one resolver attempt.
//
// PerTry on its own is an assumption about the caller. With the shipped
// defaults — len(DefaultEndpoints()) rungs at defaultPerTry — a serial walk
// costs up to 20 s while the only caller budget in the tree is 8 s, so the two
// alternate-port rungs that MEASUREMENTS.md §2 measures as the ONLY plaintext
// transport working on this line are never reached: the walk dies inside the
// DoH rungs ahead of them. Dividing what is left of the caller's deadline by
// the rungs still to try keeps the whole chain inside that deadline whatever
// the caller chose, and gives a rung its full PerTry whenever the budget is
// generous enough to afford it.
//
// There is deliberately no floor. A rung that gets 50 ms fails fast and hands
// its successor the rest, which is strictly better than one rung spending the
// entire budget on the drop-shaped censorship §2 measures.
func rungBudget(perTry, remaining time.Duration, rungsLeft int) time.Duration {
	if rungsLeft < 1 {
		rungsLeft = 1
	}
	if remaining <= 0 {
		return 0
	}
	if share := remaining / time.Duration(rungsLeft); share < perTry {
		return share
	}
	return perTry
}

// hasEncrypted reports whether the chain holds a rung that is not plaintext.
func (c *Chain) hasEncrypted() bool {
	for _, r := range c.resolvers {
		if !isPlaintext(r) {
			return true
		}
	}
	return false
}

// eligible reports whether this pass may try r.
func (st *walkState) eligible(r Resolver, mode walkMode) bool {
	if mode == walkEncryptedOnly {
		return !isPlaintext(r)
	}
	// Once a plaintext resolver has truncated, every other plaintext resolver
	// will truncate identically, so there is nothing to learn from trying one.
	return !(st.sawTrunc && isPlaintext(r))
}

// walk makes one pass over the chain, returning the first clean answer.
func (c *Chain) walk(ctx context.Context, query []byte, name string, q Question, st *walkState, mode walkMode) []byte {
	deadline, hasDeadline := ctx.Deadline()

	for i, r := range c.resolvers {
		if err := ctx.Err(); err != nil {
			st.errs = append(st.errs, err)
			return nil
		}
		if !st.eligible(r, mode) {
			continue
		}

		perTry := c.perTry
		if hasDeadline {
			left := 0
			for _, rest := range c.resolvers[i:] {
				if st.eligible(rest, mode) {
					left++
				}
			}
			// time.Now, not c.now: ctx.Deadline() is wall clock, and a test
			// clock must not be able to talk a real deadline into a longer
			// budget than the caller actually granted.
			perTry = rungBudget(c.perTry, time.Until(deadline), left)
			if perTry <= 0 {
				st.errs = append(st.errs, fmt.Errorf("%s: %w", r.Label(), context.DeadlineExceeded))
				return nil
			}
		}

		start := c.now()
		try, cancel := context.WithTimeout(ctx, perTry)
		ans, err := r.Exchange(try, query)
		cancel()
		latency := c.now().Sub(start)

		if err != nil {
			c.setHealth(Health{Label: r.Label(), Latency: latency, Err: err})
			st.errs = append(st.errs, fmt.Errorf("%s: %w", r.Label(), err))
			c.logf("resolve: %s failed %s after %s: %v", r.Label(), q, latency.Round(time.Millisecond), err)
			continue
		}

		addrs := AnswerAddrs(ans)
		sig := c.det.Check(name, addrs)
		if !sig.Poisoned {
			c.det.Learn(name, addrs)
			// Re-check after learning. The answer that completes the quorum is
			// itself poisoned; checking only before Learn is how the first
			// uniformQuorum-1 block pages were served as clean, cached, and
			// handed to the reverse map with no way to take them back.
			sig = c.det.Check(name, addrs)
		}
		if sig.Poisoned {
			c.notePoison(name, sig)
			c.setHealth(Health{Label: r.Label(), Latency: latency, Signal: sig,
				Err: fmt.Errorf("poisoned answer: %s", sig.Detail)})
			st.errs = append(st.errs, fmt.Errorf("%s: poisoned answer: %s", r.Label(), sig.Detail))
			c.logf("resolve: %s returned a poisoned answer for %s (%s); advancing the chain",
				r.Label(), name, sig.Detail)
			continue
		}

		if Truncated(ans) && isPlaintext(r) {
			st.sawTrunc = true
			st.truncated = ans
			c.setHealth(Health{Label: r.Label(), Latency: latency, Signal: sig,
				Err: errors.New("answer truncated; re-asking an encrypted resolver, never TCP")})
			c.logf("resolve: %s truncated %s; re-asking an encrypted resolver (TCP/53 is never attempted)", r.Label(), q)
			continue
		}

		c.setHealth(Health{Label: r.Label(), OK: true, Latency: latency, Signal: sig})
		return ans
	}
	return nil
}

// notePoison records positive evidence of censorship: it invalidates anything
// already served under the offending address and feeds the AAAA policy.
func (c *Chain) notePoison(name string, sig Signal) {
	if !sig.Poisoned || !sig.Addr.IsValid() {
		return
	}
	if c.markPoisoned(sig.Addr) {
		// First sighting only. The uniqueness heuristic needs uniformQuorum
		// distinct names before it fires, so by the time it does, answers
		// carrying the same censored address have already been served as clean
		// and cached; nothing else in the chain can take them back. Gating on
		// the first sighting keeps a network where every blocked name is
		// poisoned from flushing the cache once per query.
		c.Flush()
		c.logf("resolve: %s was caught poisoning this network (%s); flushed the answer cache", sig.Addr, sig.Detail)
	}
	// Only the address that actually matched the sinkhole may condemn IPv6.
	// Scanning the whole answer for any IPv6 address blames a legitimate AAAA
	// that merely shared a message with the IPv4 sentinel, and v6Poisoned has
	// no expiry, so one mis-attribution amputates AAAA for the life of the
	// Chain under AAAAAuto.
	if sig.Sinkhole && sig.Addr.Is6() && !sig.Addr.Is4In6() {
		c.aaaa.noteV6Poison(fmt.Sprintf("an IPv6 answer for %s was the sinkhole %s", name, sig.Addr))
	}
}

// markPoisoned records an address as known-censored and reports whether this is
// the first time it has been seen.
func (c *Chain) markPoisoned(a netip.Addr) bool {
	c.poisonMu.Lock()
	defer c.poisonMu.Unlock()
	if c.poisonSeen == nil {
		c.poisonSeen = make(map[netip.Addr]bool)
	}
	if c.poisonSeen[a] {
		return false
	}
	c.poisonSeen[a] = true
	return true
}

// Flush drops every cached answer.
//
// The chain has no other way to withdraw an answer it has already handed out.
// Anything that learns the network is lying — a newly caught sinkhole, a
// uniqueness quorum reaching its threshold — has to be able to invalidate what
// was served before the evidence arrived.
func (c *Chain) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[cacheKey]cacheEntry)
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

// withCallerID returns a copy of a cached answer carrying the caller's own
// header ID and question bytes.
//
// The ID is not enough. cacheKey and FirstQuestion both lower-case the name, so
// a cached answer carries whatever case the first caller used. RFC 1035 §4.1.2
// has the responder copy the question from the request, and a stub using 0x20
// case randomisation compares it byte for byte: a reply whose question reads
// "discord.com." when it asked "DiScOrD.CoM." is treated as a spoof and
// dropped, which is a silent resolution failure with no error anywhere.
func (c *Chain) withCallerID(query, cached []byte) []byte {
	out := make([]byte, len(cached))
	copy(out, cached)
	if id, err := MsgID(query); err == nil {
		_ = SetMsgID(out, id)
	}
	qe, qerr := questionEnd(query)
	ce, cerr := questionEnd(out)
	// Equal lengths are expected — same name, same labels, only the case can
	// differ — but a mismatch means the two messages are not shaped alike, and
	// splicing would corrupt the answer. Keep the ID-only patch in that case.
	if qerr != nil || cerr != nil || qe != ce || qe > len(out) || qe > len(query) {
		return out
	}
	copy(out[headerLen:qe], query[headerLen:qe])
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
