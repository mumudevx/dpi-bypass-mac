package resolve

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// The fail-closed half of the AAAA policy.
//
// DOSSIER GT19 records the IPv6 sinkhole 2a01:358:4014:a00::3 as registered in
// RIPE to BTK itself, so AAAA poisoning is half the block on this line. The
// defect this closes is subtler than a poisoned answer, though: a tool that
// answers AAAA with REAL records while capturing only IPv4 hands applications
// addresses for traffic it cannot protect, and everything looks like it is
// working. So an answer that leaves this process is withheld unless something
// is actually carrying IPv6 — and "nobody wired the predicate" counts as
// nothing carrying it.

func alwaysTrue() bool  { return true }
func alwaysFalse() bool { return false }

func TestAAAAPolicySuppressesServedAnswersWhenIPv6IsUnprotected(t *testing.T) {
	t.Parallel()
	p := &aaaaPolicy{mode: AAAAAuto, v4Path: alwaysTrue} // no v6Path: nobody claimed IPv6
	ok, why := p.allowServed(context.Background())
	if ok {
		t.Fatal("an AAAA answer was served while nothing was carrying IPv6")
	}
	if !strings.Contains(why, "IPv6") {
		t.Errorf("the reason must say what is missing: %q", why)
	}
	// dpb's own lookups are unaffected: whatever this process dials, it dials
	// through the ladder, in either family.
	if ok, _ := p.allow(context.Background()); !ok {
		t.Fatal("the process's own AAAA lookups were suppressed; only served answers are gated")
	}
}

func TestAAAAPolicyServesAAAAWhenIPv6IsCaptured(t *testing.T) {
	t.Parallel()
	p := &aaaaPolicy{mode: AAAAAuto, v4Path: alwaysTrue, v6Path: alwaysTrue}
	if ok, why := p.allowServed(context.Background()); !ok {
		t.Fatalf("AAAA was suppressed on a tunnel that is carrying IPv6: %q", why)
	}
	// Poison evidence still suppresses, capture or no capture: a sinkholed
	// address is not made safe by being routed through us.
	p.noteV6Poison("an IPv6 answer for discord.com was the sinkhole 2a01:358:4014:a00::3")
	if ok, _ := p.allowServed(context.Background()); ok {
		t.Fatal("a poisoned AAAA was served because IPv6 was captured")
	}
}

// TestAAAAPolicyEscapesApplyToTheServedRule too: suppression is a total outage
// on a v6-only or 464XLAT network, which is worse than the leak it prevents.
func TestAAAAPolicyEscapesApplyToTheServedRule(t *testing.T) {
	t.Parallel()
	noV4 := &aaaaPolicy{mode: AAAAAuto, v4Path: alwaysFalse}
	if ok, _ := noV4.allowServed(context.Background()); !ok {
		t.Fatal("AAAA was suppressed with no IPv4 path: that leaves nothing to connect with")
	}
	nat := &aaaaPolicy{
		mode:   AAAAAuto,
		v4Path: alwaysTrue,
		nat64:  func(context.Context) NAT64 { return NAT64{Detected: true} },
	}
	if ok, _ := nat.allowServed(context.Background()); !ok {
		t.Fatal("AAAA was suppressed behind NAT64, where the AAAA is the connectivity")
	}
	allow := &aaaaPolicy{mode: AAAAAllow, v4Path: alwaysTrue}
	if ok, _ := allow.allowServed(context.Background()); !ok {
		t.Fatal("ipv6 = allow must serve AAAA whatever the datapath is doing")
	}
}

// recordingResolver answers like `answering` and remembers every question it
// was asked, so a test can say "this name never left the process" instead of
// counting calls — the AAAA policy's own NAT64 probe is a real query and would
// otherwise be indistinguishable from a leak.
func recordingResolver(t *testing.T, addrs ...netip.Addr) (*fakeResolver, func() []string) {
	var (
		mu   sync.Mutex
		seen []string
	)
	r := &fakeResolver{
		label: "doh", transport: "doh", t: t,
		reply: func(t *testing.T, q []byte) []byte {
			if fq, err := FirstQuestion(q); err == nil {
				mu.Lock()
				seen = append(seen, dns.TypeToString[fq.Type]+" "+normName(fq.Name))
				mu.Unlock()
			}
			return answerFor(t, q, addrs...)
		},
	}
	return r, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// TestChainServedAAAAIsSuppressedWithoutACapture is the same rule at the seam a
// stub actually reaches: NOERROR with an SOA, never NXDOMAIN, and never a query
// for that name on the wire.
func TestChainServedAAAAIsSuppressedWithoutACapture(t *testing.T) {
	t.Parallel()
	up, asked := recordingResolver(t, netip.MustParseAddr("2606:4700::1111"))
	c := fastChain(t, Options{Resolvers: []Resolver{up}, AAAA: AAAAAuto, V4Path: alwaysTrue})

	ans, err := c.ExchangeServed(context.Background(), mustQuery(t, "discord.com", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("ExchangeServed: %v", err)
	}
	var m dns.Msg
	if err := m.Unpack(ans); err != nil {
		t.Fatal(err)
	}
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Fatalf("want NOERROR with an empty answer and one SOA, got %v", &m)
	}
	for _, q := range asked() {
		if q == "AAAA discord.com" {
			t.Fatalf("the suppressed name was queried anyway: %v", asked())
		}
	}

	// A is untouched: this is an IPv6 policy, not a resolver kill switch.
	if _, err := c.ExchangeServed(context.Background(), mustQuery(t, "discord.com", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	// And dpb's own path still resolves AAAA, because dpb protects what dpb
	// dials.
	if _, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"A discord.com": false, "AAAA discord.com": false}
	for _, q := range asked() {
		if _, ok := want[q]; ok {
			want[q] = true
		}
	}
	for q, got := range want {
		if !got {
			t.Errorf("%q never reached a resolver: %v", q, asked())
		}
	}
}

// TestChainServedAAAAFollowsTheGate: the predicate is read at answer time, not
// at construction, because the capture can go away under a running process —
// a network change, a re-verification that finds ::/1 gone, teardown.
func TestChainServedAAAAFollowsTheGate(t *testing.T) {
	t.Parallel()
	captured := false
	up := answering(t, "doh", "doh", netip.MustParseAddr("2606:4700::1111"))
	c := fastChain(t, Options{
		Resolvers:   []Resolver{up},
		AAAA:        AAAAAuto,
		V4Path:      alwaysTrue,
		V6Protected: func() bool { return captured },
	})
	q := mustQuery(t, "discord.com", dns.TypeAAAA)

	if st := c.AAAAStatus(context.Background()); st.Served || st.V6Protected {
		t.Fatalf("status = %+v, want served=false while nothing carries IPv6", st)
	}
	captured = true
	ans, err := c.ExchangeServed(context.Background(), q)
	if err != nil {
		t.Fatalf("ExchangeServed: %v", err)
	}
	var m dns.Msg
	if err := m.Unpack(ans); err != nil {
		t.Fatal(err)
	}
	if len(m.Answer) == 0 {
		t.Fatal("AAAA was suppressed while IPv6 was captured and verified")
	}
	st := c.AAAAStatus(context.Background())
	if !st.Served || !st.V6Protected || !st.Own {
		t.Fatalf("status = %+v, want everything allowed once IPv6 is captured", st)
	}
	if st.Mode != AAAAAuto {
		t.Fatalf("status mode = %s", st.Mode)
	}

	captured = false
	c.Flush() // the capture went away; the cached answer must not outlive it
	ans, err = c.ExchangeServed(context.Background(), q)
	if err != nil {
		t.Fatalf("ExchangeServed: %v", err)
	}
	m = dns.Msg{}
	if err := m.Unpack(ans); err != nil {
		t.Fatal(err)
	}
	if len(m.Answer) != 0 {
		t.Fatal("AAAA was still served after the IPv6 capture went away")
	}
	if st := c.AAAAStatus(context.Background()); st.Served || st.ServedWhy == "" {
		t.Fatalf("status = %+v, want a suppressed served answer with a reason", st)
	}
}
