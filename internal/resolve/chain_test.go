package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fastChain keeps the per-try deadline short so a dropped query — the measured
// failure mode of port 53 here — costs milliseconds in tests rather than the
// production four seconds.
func fastChain(t *testing.T, o Options) *Chain {
	t.Helper()
	if o.PerTry == 0 {
		o.PerTry = 80 * time.Millisecond
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return NewChain(o)
}

func truncating(t *testing.T, label, transport string) *fakeResolver {
	return &fakeResolver{
		label: label, transport: transport, t: t,
		reply: func(t *testing.T, q []byte) []byte {
			ans := buildAnswer(t, q, 60, genuineAnswer...)
			if ans == nil {
				return nil
			}
			ans[2] |= 0x02 // TC
			return ans
		},
	}
}

func rcodeRung(t *testing.T, label string, rcode int) *fakeResolver {
	return &fakeResolver{
		label: label, transport: "doh", t: t,
		reply: func(t *testing.T, q []byte) []byte { return SynthRcode(q, rcode) },
	}
}

type recordingReverse struct {
	mu    sync.Mutex
	names []string
	addrs []netip.Addr
	ttl   time.Duration
}

func (r *recordingReverse) Learn(name string, ips []netip.Addr, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
	r.addrs = append(r.addrs, ips...)
	r.ttl = ttl
}

func (r *recordingReverse) Lookup(netip.Addr) (string, bool) { return "", false }

func (r *recordingReverse) snapshot() ([]string, []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...), append([]netip.Addr(nil), r.addrs...)
}

// TestChainAdvancesPastADroppedQuery is MEASUREMENTS.md §2's first consequence:
// `dig @8.8.8.8 discord.com` times out while the alternate port answers, so the
// chain has to treat silence as a rung failure and keep going.
func TestChainAdvancesPastADroppedQuery(t *testing.T) {
	drop := dropping(t, "udp-53")
	alt := answering(t, "udp-alt", "udp-alt", genuineAnswer...)
	c := fastChain(t, Options{Resolvers: []Resolver{drop, alt}})

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := addrStrings(AnswerAddrs(ans)); got != addrStrings(genuineAnswer) {
		t.Fatalf("answer = %s, want the measured alt-port answer %s", got, addrStrings(genuineAnswer))
	}
	if drop.Calls() != 1 || alt.Calls() != 1 {
		t.Fatalf("calls: drop=%d alt=%d", drop.Calls(), alt.Calls())
	}
	h := c.Health()
	if len(h) != 2 || h[0].OK || h[0].Err == nil {
		t.Fatalf("the dropping rung must be reported unhealthy: %+v", h)
	}
	if !h[1].OK {
		t.Fatalf("the answering rung must be reported healthy: %+v", h[1])
	}
	if got := c.Labels(); len(got) != 2 || got[0] != "udp-53" {
		t.Fatalf("Labels = %v", got)
	}
}

// TestChainRejectsTheSinkholeAndAdvances is the §2 sinkhole rule: 195.175.254.2
// is a hard reject that advances the chain, not an answer to fall back on. A
// tool that accepts it sends every blocked flow to a blackhole, which §5.4
// records as invalidating an entire measurement run.
func TestChainRejectsTheSinkholeAndAdvances(t *testing.T) {
	bad := sinkholing(t, "isp")
	good := answering(t, "doh", "doh", genuineAnswer...)
	c := fastChain(t, Options{Resolvers: []Resolver{bad, good}})

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	for _, a := range AnswerAddrs(ans) {
		if a == ttSinkhole {
			t.Fatal("the sinkhole answer was returned to the caller")
		}
	}
	if got := addrStrings(AnswerAddrs(ans)); got != addrStrings(genuineAnswer) {
		t.Fatalf("answer = %s", got)
	}
	h := c.Health()
	if !h[0].Signal.Sinkhole {
		t.Fatalf("the sinkhole must be recorded against the rung that served it: %+v", h[0])
	}
	if !strings.Contains(h[0].Signal.Detail, "195.175.254.2") {
		t.Fatalf("detail = %q", h[0].Signal.Detail)
	}
}

// TestChainExhaustionSynthesisesSERVFAIL: the stub must get a well-formed answer
// to its own question immediately. Silence makes it wait out a timeout and then
// retry over TCP, which §2 measures as reset at every port on this ISP.
func TestChainExhaustionSynthesisesSERVFAIL(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{
		dropping(t, "a"),
		&fakeResolver{label: "b", transport: "doh", t: t, err: errors.New("refused")},
	}})

	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0xc0de); err != nil {
		t.Fatal(err)
	}
	ans, err := c.Exchange(context.Background(), q)
	if !errors.Is(err, ErrChainExhausted) {
		t.Fatalf("err = %v, want ErrChainExhausted", err)
	}
	if Rcode(ans) != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", Rcode(ans))
	}
	if id, _ := MsgID(ans); id != 0xc0de {
		t.Fatalf("the caller's ID must survive, got %#x", id)
	}
	if !SameQuestion(q, ans) {
		t.Fatal("the caller's question must be echoed")
	}
	var parsed dns.Msg
	if err := parsed.Unpack(ans); err != nil {
		t.Fatalf("the synthesised answer must be well formed: %v", err)
	}
}

func TestChainWithNoResolvers(t *testing.T) {
	c := fastChain(t, Options{})
	q := mustQuery(t, "discord.com", dns.TypeA)
	ans, err := c.Exchange(context.Background(), q)
	if !errors.Is(err, ErrNoResolvers) {
		t.Fatalf("err = %v", err)
	}
	if Rcode(ans) != dns.RcodeServerFailure {
		t.Fatalf("an empty chain must still answer SERVFAIL, got rcode %d", Rcode(ans))
	}
}

func TestChainRejectsAnUnusableQuery(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{answering(t, "a", "doh", genuineAnswer[0])}})
	broken := make([]byte, headerLen)
	broken[4], broken[5] = 0, 1 // qdcount = 1 with no question behind it
	ans, err := c.Exchange(context.Background(), broken)
	if err == nil {
		t.Fatal("an unusable query must be reported")
	}
	if Rcode(ans) != dns.RcodeFormatError {
		t.Fatalf("rcode = %d, want FORMERR", Rcode(ans))
	}
}

func TestChainCachesPositiveAnswers(t *testing.T) {
	up := answering(t, "doh", "doh", genuineAnswer...)
	c := fastChain(t, Options{Resolvers: []Resolver{up}, CacheTTL: time.Minute})

	q1 := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q1, 0x1111); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(context.Background(), q1); err != nil {
		t.Fatal(err)
	}
	q2 := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q2, 0x2222); err != nil {
		t.Fatal(err)
	}
	ans2, err := c.Exchange(context.Background(), q2)
	if err != nil {
		t.Fatal(err)
	}
	if up.Calls() != 1 {
		t.Fatalf("the second query must be served from cache, upstream calls = %d", up.Calls())
	}
	if id, _ := MsgID(ans2); id != 0x2222 {
		t.Fatalf("a cached answer must carry the new caller's ID, got %#x", id)
	}
	if got := addrStrings(AnswerAddrs(ans2)); got != addrStrings(genuineAnswer) {
		t.Fatalf("cached answer = %s", got)
	}
}

func TestChainCachesNegativeAnswersBriefly(t *testing.T) {
	up := rcodeRung(t, "doh", dns.RcodeNameError)
	now := time.Now()
	clock := func() time.Time { return now }
	c := fastChain(t, Options{Resolvers: []Resolver{up}, NegTTL: 5 * time.Second, Now: clock})

	for range 3 {
		if _, err := c.Exchange(context.Background(), mustQuery(t, "nope.example", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	if up.Calls() != 1 {
		t.Fatalf("an NXDOMAIN must be cached, upstream calls = %d", up.Calls())
	}
	// A negative answer here is as likely to be a censored transport as a real
	// absence, so it must expire quickly and be retried.
	now = now.Add(6 * time.Second)
	if _, err := c.Exchange(context.Background(), mustQuery(t, "nope.example", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if up.Calls() != 2 {
		t.Fatalf("the negative entry must expire, upstream calls = %d", up.Calls())
	}
}

// TestChainSkipsPlaintextAfterTruncation encodes §2's hardest rule: the RFC
// answer to TC=1 is "retry over TCP", and TCP DNS is connection-reset at every
// port here. The only correct move is to re-ask an encrypted resolver.
func TestChainSkipsPlaintextAfterTruncation(t *testing.T) {
	trunc := truncating(t, "udp-alt-1", "udp-alt")
	otherUDP := answering(t, "udp-alt-2", "udp-alt", genuineAnswer[0])
	doh := answering(t, "doh", "doh", genuineAnswer...)
	c := fastChain(t, Options{Resolvers: []Resolver{trunc, otherUDP, doh}})

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if Truncated(ans) {
		t.Fatal("the truncated answer must not be the one returned")
	}
	if otherUDP.Calls() != 0 {
		t.Fatalf("a second plaintext rung truncates identically and must be skipped, calls = %d", otherUDP.Calls())
	}
	if doh.Calls() != 1 {
		t.Fatalf("the encrypted rung must be asked, calls = %d", doh.Calls())
	}
}

func TestChainReturnsTruncatedRatherThanFallingBackToTCP(t *testing.T) {
	trunc := truncating(t, "udp-alt", "udp-alt")
	c := fastChain(t, Options{Resolvers: []Resolver{trunc}})
	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !Truncated(ans) {
		t.Fatal("with no encrypted rung left, the truncated answer is what the stub gets")
	}
	// A truncated answer is a transport artefact, not a result: caching it
	// would hand every later caller a TC=1 they can only act on over TCP.
	if _, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if trunc.Calls() != 2 {
		t.Fatalf("a truncated answer must not be cached, upstream calls = %d", trunc.Calls())
	}
}

func TestChainFeedsTheReverseMap(t *testing.T) {
	rev := &recordingReverse{}
	c := fastChain(t, Options{
		Resolvers: []Resolver{answering(t, "doh", "doh", genuineAnswer...)},
		Reverse:   rev,
	})
	if _, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	names, addrs := rev.snapshot()
	if len(names) != 1 || names[0] != "discord.com" {
		t.Fatalf("names = %v", names)
	}
	if addrStrings(addrs) != addrStrings(genuineAnswer) {
		t.Fatalf("addrs = %s", addrStrings(addrs))
	}
}

// TestChainAAAASuppressNeverLeavesTheProcess: a suppressed AAAA must not cost a
// query, and must never be NXDOMAIN.
func TestChainAAAASuppressNeverLeavesTheProcess(t *testing.T) {
	up := answering(t, "doh", "doh", netip.MustParseAddr("2606:4700::1111"))
	c := fastChain(t, Options{Resolvers: []Resolver{up}, AAAA: AAAASuppress})

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if up.Calls() != 0 {
		t.Fatalf("a suppressed AAAA must not reach a resolver, calls = %d", up.Calls())
	}
	var m dns.Msg
	if err := m.Unpack(ans); err != nil {
		t.Fatal(err)
	}
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Fatalf("want NOERROR with an empty answer and one SOA, got %v", m)
	}
	// A is untouched by the policy.
	if _, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if up.Calls() != 1 {
		t.Fatalf("A must still be resolved, calls = %d", up.Calls())
	}
}

// TestChainAAAAAutoWaitsForEvidence: AAAAAuto must not amputate IPv6 on a clean
// network. It suppresses only after an IPv6 answer here was caught as the BTK
// sinkhole, with a verified v4 path and no NAT64.
func TestChainAAAAAutoWaitsForEvidence(t *testing.T) {
	v6Sinkhole := netip.MustParseAddr("2a01:358:4014:a00::3")
	poisoned := &fakeResolver{
		label: "isp", transport: "udp", t: t,
		reply: func(t *testing.T, q []byte) []byte {
			fq, err := FirstQuestion(q)
			if err != nil || fq.Type != dns.TypeAAAA {
				return buildAnswer(t, q, 60, genuineAnswer[0])
			}
			return buildAnswer(t, q, 60, v6Sinkhole)
		},
	}
	clean := answering(t, "doh", "doh", netip.MustParseAddr("2606:4700::1111"), genuineAnswer[0])
	c := fastChain(t, Options{
		Resolvers: []Resolver{poisoned, clean},
		AAAA:      AAAAAuto,
		V4Path:    func() bool { return true },
	})

	// Before any evidence, AAAA flows normally.
	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(AnswerAddrs(ans)) == 0 {
		t.Fatal("the clean rung's AAAA must be returned")
	}

	// The sinkholed AAAA is the positive evidence. A later AAAA for a different
	// name is now suppressed rather than risked.
	ans2, err := c.Exchange(context.Background(), mustQuery(t, "discord.gg", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	var m dns.Msg
	if err := m.Unpack(ans2); err != nil {
		t.Fatal(err)
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("suppression must be NOERROR, never NXDOMAIN, got %s", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Fatalf("AAAA must be suppressed after the evidence, got %v", m.Answer)
	}
}

// TestChainAAAAAutoKeepsAAAAWithoutAV4Path: suppressing AAAA on a network with
// no IPv4 leaves the user with nothing at all.
func TestChainAAAAAutoKeepsAAAAWithoutAV4Path(t *testing.T) {
	v6Sinkhole := netip.MustParseAddr("2a01:358:4014:a00::3")
	c := fastChain(t, Options{
		Resolvers: []Resolver{sinkholing(t, "isp"), answering(t, "doh", "doh", netip.MustParseAddr("2606:4700::1111"))},
		AAAA:      AAAAAuto,
		V4Path:    func() bool { return false },
	})
	c.aaaa.noteV6Poison("an IPv6 answer was " + v6Sinkhole.String())

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(AnswerAddrs(ans)) == 0 {
		t.Fatal("with no v4 path, AAAA must survive even after a poisoned answer")
	}
}

// TestChainAAAAAutoKeepsAAAAUnderNAT64: on a 464XLAT carrier the AAAA is the
// connectivity, so DNS64 synthesis must veto suppression.
func TestChainAAAAAutoKeepsAAAAUnderNAT64(t *testing.T) {
	synth := netip.MustParseAddr("64:ff9b::c000:aa") // 64:ff9b::192.0.0.170
	up := &fakeResolver{
		label: "doh", transport: "doh", t: t,
		reply: func(t *testing.T, q []byte) []byte {
			fq, err := FirstQuestion(q)
			if err != nil {
				return nil
			}
			if fq.Name == nat64Probe {
				return buildAnswer(t, q, 60, synth)
			}
			return buildAnswer(t, q, 60, netip.MustParseAddr("2606:4700::1111"))
		},
	}
	c := fastChain(t, Options{Resolvers: []Resolver{up}, AAAA: AAAAAuto, V4Path: func() bool { return true }})
	c.aaaa.noteV6Poison("an IPv6 answer was the sinkhole")

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(AnswerAddrs(ans)) == 0 {
		t.Fatal("NAT64 must veto AAAA suppression")
	}
	if n := c.nat64Cached(context.Background()); !n.Detected || len(n.Prefixes) != 1 {
		t.Fatalf("NAT64 detection = %+v", n)
	}
}

func TestChainNAT64ProbeFailureIsNotDetection(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{dropping(t, "a")}})
	n := c.detectNAT64(context.Background())
	if n.Detected {
		t.Fatalf("a failed probe must not report NAT64: %+v", n)
	}
	if n.Detail == "" {
		t.Fatal("a failed probe must say why")
	}
	// A NOERROR answer with no AAAA is the normal, non-DNS64 case.
	c2 := fastChain(t, Options{Resolvers: []Resolver{rcodeRung(t, "a", dns.RcodeSuccess)}})
	if n := c2.detectNAT64(context.Background()); n.Detected {
		t.Fatalf("no synthesised AAAA means no NAT64: %+v", n)
	}
}

func TestChainNAT64ResultIsMemoised(t *testing.T) {
	up := answering(t, "doh", "doh", netip.MustParseAddr("64:ff9b::c000:aa"))
	now := time.Now()
	c := fastChain(t, Options{Resolvers: []Resolver{up}, Now: func() time.Time { return now }})
	first := c.nat64Cached(context.Background())
	second := c.nat64Cached(context.Background())
	if !first.Detected || !second.Detected {
		t.Fatalf("detection = %+v / %+v", first, second)
	}
	if up.Calls() != 1 {
		t.Fatalf("the probe must be memoised, calls = %d", up.Calls())
	}
	now = now.Add(nat64TTL + time.Second)
	c.nat64Cached(context.Background())
	if up.Calls() != 2 {
		t.Fatalf("the memo must expire, calls = %d", up.Calls())
	}
}

func TestResolveReturnsIPLiteralsUntouched(t *testing.T) {
	up := answering(t, "doh", "doh", genuineAnswer...)
	c := fastChain(t, Options{Resolvers: []Resolver{up}})
	for _, in := range []string{"162.159.128.233", "[2606:4700::1111]", "::ffff:1.2.3.4"} {
		got, err := c.Resolve(context.Background(), in)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", in, err)
		}
		if len(got) != 1 {
			t.Fatalf("Resolve(%q) = %v", in, got)
		}
	}
	if up.Calls() != 0 {
		t.Fatalf("an IP literal must never be queried, calls = %d", up.Calls())
	}
	if _, err := c.Resolve(context.Background(), "  "); err == nil {
		t.Fatal("an empty host must be refused")
	}
}

func TestResolveRunsBothFamiliesAndPrefersIPv4(t *testing.T) {
	v6 := netip.MustParseAddr("2606:4700::1111")
	up := &fakeResolver{
		label: "doh", transport: "doh", t: t,
		reply: func(t *testing.T, q []byte) []byte {
			return answerFor(t, q, genuineAnswer[0], genuineAnswer[1], v6)
		},
	}
	c := fastChain(t, Options{Resolvers: []Resolver{up}, AAAA: AAAAAllow})
	got, err := c.Resolve(context.Background(), "Discord.Com.")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("both families must be returned, got %v", got)
	}
	if !got[0].Is4() || !got[1].Is4() || got[2] != v6 {
		t.Fatalf("IPv4 must come first (DOSSIER GT19 records a BTK IPv6 sinkhole), got %v", got)
	}
	if up.Calls() != 2 {
		t.Fatalf("A and AAAA must both be asked, calls = %d", up.Calls())
	}
}

func TestResolveReportsNoAddress(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{rcodeRung(t, "doh", dns.RcodeSuccess)}, AAAA: AAAAAllow})
	if _, err := c.Resolve(context.Background(), "empty.example"); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("err = %v, want ErrNoAddress", err)
	}
}

func TestResolveReportsChainFailure(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{dropping(t, "a")}, AAAA: AAAAAllow})
	_, err := c.Resolve(context.Background(), "discord.com")
	if !errors.Is(err, ErrChainExhausted) {
		t.Fatalf("err = %v, want ErrChainExhausted", err)
	}
	if !strings.Contains(err.Error(), "discord.com") {
		t.Fatalf("the error must name the host: %v", err)
	}
}

func TestResolveReportsRcode(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{rcodeRung(t, "doh", dns.RcodeNameError)}, AAAA: AAAAAllow})
	_, err := c.Resolve(context.Background(), "nope.example")
	if err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Fatalf("err = %v", err)
	}
}

func TestChainHonoursTheCallerContext(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{dropping(t, "a"), dropping(t, "b")}, PerTry: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err == nil {
		t.Fatal("a cancelled context must end the walk")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the walk ignored the caller's deadline: %s", d)
	}
}

func TestChainCacheEviction(t *testing.T) {
	now := time.Now()
	c := fastChain(t, Options{
		Resolvers: []Resolver{answering(t, "doh", "doh", genuineAnswer[0])},
		Now:       func() time.Time { return now },
		CacheTTL:  time.Minute,
	})
	// Fill past the cap; the map must not grow without bound.
	for i := range cacheMax + 50 {
		k := cacheKey{name: "n" + string(rune('a'+i%26)) + string(rune(i)), qtype: dns.TypeA, class: dns.ClassINET}
		c.cachePut(k, buildAnswer(t, mustQuery(t, "discord.com", dns.TypeA), 60, genuineAnswer[0]), mustMsg(t, genuineAnswer[0]), time.Minute)
	}
	c.mu.Lock()
	size := len(c.cache)
	c.mu.Unlock()
	if size > cacheMax {
		t.Fatalf("cache grew to %d, above the %d cap", size, cacheMax)
	}
	// An expired entry is not served.
	k := cacheKey{name: "x.", qtype: dns.TypeA, class: dns.ClassINET}
	c.cachePut(k, buildAnswer(t, mustQuery(t, "discord.com", dns.TypeA), 60, genuineAnswer[0]), mustMsg(t, genuineAnswer[0]), time.Second)
	now = now.Add(2 * time.Second)
	if _, ok := c.cacheGet(k); ok {
		t.Fatal("an expired entry must not be served")
	}
}

func mustMsg(t *testing.T, addr netip.Addr) *dns.Msg {
	t.Helper()
	ans := buildAnswer(t, mustQuery(t, "discord.com", dns.TypeA), 60, addr)
	m, err := unpack(ans)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestChainDefaultsAreUsable(t *testing.T) {
	c := NewChain(Options{})
	if c == nil {
		t.Fatal("NewChain must never return nil")
	}
	if c.perTry != defaultPerTry || c.cacheTTL != defaultCacheTTL || c.negTTL != defaultNegTTL {
		t.Fatalf("defaults not applied: %s %s %s", c.perTry, c.cacheTTL, c.negTTL)
	}
	if c.det == nil {
		t.Fatal("a chain without a detector would approve the sinkhole")
	}
	if got := c.Health(); len(got) != 0 {
		t.Fatalf("Health = %v", got)
	}
}

// flakyResolver fails its first exchange and answers every one after it. It is
// how a transient failure on an encrypted rung is expressed: the rung is not
// dead, it just lost this attempt.
type flakyResolver struct {
	label     string
	transport string
	t         *testing.T
	mu        sync.Mutex
	n         int
}

func (f *flakyResolver) Label() string     { return f.label }
func (f *flakyResolver) Transport() string { return f.transport }

func (f *flakyResolver) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

func (f *flakyResolver) Exchange(_ context.Context, q []byte) ([]byte, error) {
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	if n == 1 {
		return nil, errors.New("transient failure")
	}
	return answerFor(f.t, q, genuineAnswer[0]), nil
}

// TestRungBudgetFitsTheShippedDefaults pins the arithmetic that makes the whole
// chain reachable.
//
// The shipped chain is len(DefaultEndpoints()) rungs at defaultPerTry, and the
// only caller budget in the tree is probe.DefaultTrialTimeout at 8 s. A flat
// per-rung deadline spends 4 s on rung 1, 4 s on rung 2 and then runs out —
// which is how the two alternate-port rungs that MEASUREMENTS.md §2 measures as
// the ONLY plaintext transport working on this line became unreachable.
func TestRungBudgetFitsTheShippedDefaults(t *testing.T) {
	const callerBudget = 8 * time.Second
	rungs := len(DefaultEndpoints())

	// The shipped chain walked under the shipped caller budget: every rung has
	// to fit, and the sum has to stay inside the budget.
	total := time.Duration(0)
	remaining := callerBudget
	for left := rungs; left > 0; left-- {
		b := rungBudget(defaultPerTry, remaining, left)
		if b <= 0 {
			t.Fatalf("rung %d of %d got no budget out of %s", rungs-left+1, rungs, callerBudget)
		}
		total += b
		remaining -= b
	}
	if total > callerBudget {
		t.Fatalf("the walk costs %s against a %s caller budget", total, callerBudget)
	}
	if got := rungBudget(defaultPerTry, callerBudget, rungs); got != callerBudget/time.Duration(rungs) {
		t.Fatalf("rungBudget = %s, want an even share of %s across %d rungs", got, callerBudget, rungs)
	}

	// A generous budget must not stretch a rung past PerTry.
	if got := rungBudget(defaultPerTry, time.Hour, 1); got != defaultPerTry {
		t.Fatalf("rungBudget = %s, want PerTry %s", got, defaultPerTry)
	}
	// A spent budget buys nothing, and a bad rung count must not divide by zero.
	if got := rungBudget(defaultPerTry, -time.Second, 3); got != 0 {
		t.Fatalf("rungBudget on a spent budget = %s, want 0", got)
	}
	if got := rungBudget(defaultPerTry, time.Second, 0); got != time.Second {
		t.Fatalf("rungBudget with no rungs left = %s, want the whole remainder", got)
	}
}

// TestChainReachesTheLastRungInsideTheCallerDeadline is the same defect on the
// wire, and it deliberately does NOT use fastChain: the point is that the
// SHIPPED PerTry, over a chain as long as the SHIPPED one, still lands inside
// the caller's deadline. Nothing here overrides Options.PerTry, so defaultPerTry
// is what is under test.
//
// The budget is scaled down from probe.DefaultTrialTimeout only so the test is
// fast; the ratio is what matters and it is worse here than in production
// (1.5 s against a 4 s PerTry, versus 8 s against the same 4 s), so a chain that
// passes this cannot fail the shipped arithmetic.
func TestChainReachesTheLastRungInsideTheCallerDeadline(t *testing.T) {
	n := len(DefaultEndpoints())
	rungs := make([]Resolver, 0, n)
	drops := make([]*fakeResolver, 0, n-1)
	for i := range n - 1 {
		d := dropping(t, fmt.Sprintf("drop-%d", i))
		drops = append(drops, d)
		rungs = append(rungs, d)
	}
	last := answering(t, "udp-alt-last", "udp-alt", genuineAnswer[0])
	rungs = append(rungs, last)

	c := NewChain(Options{Resolvers: rungs, Logf: func(string, ...any) {}})
	if c.perTry != defaultPerTry {
		t.Fatalf("this test must run at the shipped PerTry, got %s", c.perTry)
	}

	const budget = 1500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	start := time.Now()
	ans, err := c.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exchange: %v (after %s)", err, elapsed)
	}
	if got := addrStrings(AnswerAddrs(ans)); got != genuineAnswer[0].String() {
		t.Fatalf("answer = %s, want the last rung's %s", got, genuineAnswer[0])
	}
	if last.Calls() != 1 {
		t.Fatalf("the alternate-port rung was reached %d times, want 1", last.Calls())
	}
	for i, d := range drops {
		if d.Calls() != 1 {
			t.Fatalf("rung %d was tried %d times, want 1", i, d.Calls())
		}
	}
	if elapsed > budget {
		t.Fatalf("the walk took %s, past the caller's %s deadline", elapsed, budget)
	}
}

// TestChainRestartsAtAnEncryptedRungOnTruncation pins the truncation design
// that DefaultEndpoints' own ordering made unreachable: all three encrypted
// rungs sit BEFORE both plaintext rungs, so "continue forward to an encrypted
// resolver" can never find one. MEASUREMENTS.md §2 rules out the RFC's TCP
// retry, so restarting the walk is the only move left.
func TestChainRestartsAtAnEncryptedRungOnTruncation(t *testing.T) {
	doh := &flakyResolver{label: "doh", transport: "doh", t: t}
	trunc := truncating(t, "udp-alt", "udp-alt")
	c := fastChain(t, Options{Resolvers: []Resolver{doh, trunc}})

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if Truncated(ans) {
		t.Fatal("the walk must restart at the encrypted rung rather than hand back TC=1")
	}
	if doh.Calls() != 2 {
		t.Fatalf("the encrypted rung was tried %d times, want 2 (the walk restarts at it)", doh.Calls())
	}
	if trunc.Calls() != 1 {
		t.Fatalf("the plaintext rung was tried %d times, want 1", trunc.Calls())
	}
	if got := addrStrings(AnswerAddrs(ans)); got != genuineAnswer[0].String() {
		t.Fatalf("answer = %s, want %s", got, genuineAnswer[0])
	}
}

// TestChainTruncationRetryStaysInsideTheCallerDeadline: the restart is an extra
// pass, so it must be paid for out of what is left of the caller's budget and
// never out of a fresh one.
func TestChainTruncationRetryStaysInsideTheCallerDeadline(t *testing.T) {
	doh := dropping(t, "doh")
	doh.transport = "doh"
	trunc := truncating(t, "udp-alt", "udp-alt")
	c := NewChain(Options{Resolvers: []Resolver{doh, trunc}, Logf: func(string, ...any) {}})

	const budget = 600 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	start := time.Now()
	ans, err := c.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !Truncated(ans) {
		t.Fatal("with no encrypted rung left, the truncated answer is what the caller gets")
	}
	if elapsed > budget+250*time.Millisecond {
		t.Fatalf("the walk plus its truncation retry took %s, past the caller's %s deadline", elapsed, budget)
	}
}

// TestCachedAnswerCarriesTheCallersQuestionBytes pins RFC 1035 §4.1.2 for the
// cache path. cacheKey and FirstQuestion both lower-case, so a stub using 0x20
// case randomisation would get back a question it did not ask and drop the
// reply as a spoof — a silent resolution failure with no error anywhere.
func TestCachedAnswerCarriesTheCallersQuestionBytes(t *testing.T) {
	up := answering(t, "up", "doh", genuineAnswer[0])
	c := fastChain(t, Options{Resolvers: []Resolver{up}, CacheTTL: time.Minute})

	if _, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA)); err != nil {
		t.Fatalf("priming Exchange: %v", err)
	}

	mixed := mustQuery(t, "discord.com", dns.TypeA)
	copy(mixed[headerLen+1:], []byte("DiScOrD"))
	if err := SetMsgID(mixed, 0x4242); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Exchange(context.Background(), mixed)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if up.Calls() != 1 {
		t.Fatalf("the second query must be served from cache, upstream calls = %d", up.Calls())
	}
	qe, err := questionEnd(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp[headerLen:qe]) != string(mixed[headerLen:qe]) {
		t.Fatalf("question = %q, want the caller's own %q", resp[headerLen:qe], mixed[headerLen:qe])
	}
	if id, _ := MsgID(resp); id != 0x4242 {
		t.Fatalf("id = %#x, want the caller's 0x4242", id)
	}
	if got := addrStrings(AnswerAddrs(resp)); got != genuineAnswer[0].String() {
		t.Fatalf("the answer section must survive the splice: %s", got)
	}
}

// TestChainInvalidatesWhatItServedBeforeThePoisonWasProved covers the second
// half of the poison defect: the uniqueness heuristic needs uniformQuorum
// distinct names, so the first uniformQuorum-1 block pages are served as clean
// and cached. Without an invalidation path they keep being served until the TTL
// expires, long after the chain knows better.
func TestChainInvalidatesWhatItServedBeforeThePoisonWasProved(t *testing.T) {
	block := netip.MustParseAddr("10.9.9.1")
	rung := &fakeResolver{label: "up", transport: "udp-alt", t: t,
		reply: func(t *testing.T, q []byte) []byte { return answerFor(t, q, block) }}
	c := fastChain(t, Options{Resolvers: []Resolver{rung}, CacheTTL: time.Minute})

	for _, n := range DefaultPoisonProbes {
		_, _ = c.Exchange(context.Background(), mustQuery(t, n, dns.TypeA))
	}
	ans, err := c.Exchange(context.Background(), mustQuery(t, DefaultPoisonProbes[0], dns.TypeA))
	if err == nil {
		t.Fatalf("the block page must not keep being served from cache: %v", AnswerAddrs(ans))
	}
	if rc := Rcode(ans); rc != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", rc)
	}
}

// TestChainCatchesTheAnswerThatCompletesTheQuorum: Learn used to run before
// Check for the same name, so the answer that pushed the heuristic over its
// threshold was itself scored clean and served.
func TestChainCatchesTheAnswerThatCompletesTheQuorum(t *testing.T) {
	block := []netip.Addr{netip.MustParseAddr("10.9.9.1"), netip.MustParseAddr("10.9.9.2")}
	rung := &fakeResolver{label: "up", transport: "udp-alt", t: t,
		reply: func(t *testing.T, q []byte) []byte { return answerFor(t, q, block...) }}
	c := fastChain(t, Options{Resolvers: []Resolver{rung}, CacheTTL: time.Minute})

	last := DefaultPoisonProbes[len(DefaultPoisonProbes)-1]
	for _, n := range DefaultPoisonProbes[:len(DefaultPoisonProbes)-1] {
		_, _ = c.Exchange(context.Background(), mustQuery(t, n, dns.TypeA))
	}
	ans, err := c.Exchange(context.Background(), mustQuery(t, last, dns.TypeA))
	if err == nil {
		t.Fatalf("%s completed the quorum and must not be served: %v", last, AnswerAddrs(ans))
	}
}

// TestNotePoisonBlamesOnlyTheAddressThatMatched: an IPv4 sinkhole verdict on a
// message that also carries a legitimate IPv6 record must not latch v6Poisoned,
// which has no expiry and would amputate AAAA for the life of the Chain.
func TestNotePoisonBlamesOnlyTheAddressThatMatched(t *testing.T) {
	c := fastChain(t, Options{Resolvers: []Resolver{answering(t, "x", "udp-alt", genuineAnswer[0])}})
	c.notePoison("discord.com", Signal{
		Poisoned: true, Sinkhole: true, Addr: ttSinkhole,
		Detail: "sinkhole",
	})
	if seen, why := c.aaaa.v6PoisonSeen(); seen {
		t.Fatalf("an IPv4 sinkhole must not condemn IPv6: %s", why)
	}

	v6 := netip.MustParseAddr("2a01:358:4014:a00::3")
	c.notePoison("discord.com", Signal{Poisoned: true, Sinkhole: true, Addr: v6, Detail: "sinkhole"})
	seen, why := c.aaaa.v6PoisonSeen()
	if !seen {
		t.Fatal("an IPv6 sinkhole is the positive evidence AAAAAuto waits for")
	}
	if !strings.Contains(why, v6.String()) {
		t.Fatalf("the reason must name the address that matched, got %q", why)
	}
}

// TestChainCachesNoDataBriefly pins cachePut's promise for the NOERROR /
// zero-answer reply a filtering resolver returns (and the one SynthEmpty
// produces): it is a negative answer and gets negTTL, never the positive
// cacheTTL, so a censored transport gets another chance soon.
func TestChainCachesNoDataBriefly(t *testing.T) {
	now := time.Now()
	nodata := &fakeResolver{label: "up", transport: "udp-alt", t: t,
		reply: func(t *testing.T, q []byte) []byte { return SynthEmpty(q) }}
	c := fastChain(t, Options{
		Resolvers: []Resolver{nodata},
		CacheTTL:  time.Hour,
		NegTTL:    5 * time.Second,
		Now:       func() time.Time { return now },
	})
	q := mustQuery(t, "discord.com", dns.TypeA)
	if _, err := c.Exchange(context.Background(), q); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	key := cacheKey{name: "discord.com", qtype: dns.TypeA, class: dns.ClassINET}
	e, ok := c.cache[key]
	if !ok {
		t.Fatal("a NOERROR/no-answer reply is still cached, briefly")
	}
	if got := e.exp.Sub(now); got != 5*time.Second {
		t.Fatalf("NODATA cached for %s, want the %s negative TTL and never the %s positive one",
			got, 5*time.Second, time.Hour)
	}
}
