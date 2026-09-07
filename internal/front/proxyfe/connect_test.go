package proxyfe_test

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/testcensor"
)

func openStore(t *testing.T) policy.Store {
	t.Helper()
	s, err := policy.OpenStore(filepath.Join(t.TempDir(), "verdicts.json"), time.Now)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func verdictOf(t *testing.T, s policy.Store, host string) policy.Verdict {
	t.Helper()
	v, ok := s.Get(policy.NetworkID{}, host)
	if !ok {
		t.Fatalf("no verdict cached for %s", host)
	}
	return v
}

// The M11 acceptance, offline: a censored name reaches the origin through the
// proxy, and the client sees ONE continuous TLS stream across the retry.
func TestCONNECTEscalatesOnceThroughTheSharedLadder(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026(), "discord.com")
	d := newMapDialer()
	d.add("discord.com", l.addr())
	store := openStore(t)

	h := serveTest(t, wiring{dialer: d, store: store})

	tunnel, status := h.connect(t, "discord.com:443")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	body, err := tlsThrough(t, tunnel, "discord.com", l.origin.ClientConfig("discord.com"))
	if err != nil {
		t.Fatalf("TLS through the tunnel: %v", err)
	}
	if body != labResponse {
		t.Fatalf("client read %q, want %q: the stream lost or duplicated bytes across the retry", body, labResponse)
	}

	if got := len(d.calls()); got != 2 {
		t.Fatalf("%d upstream dials, want 2 (plain then tlsfrag): %v", got, d.calls())
	}
	v := verdictOf(t, store, "discord.com")
	if v.Source != policy.SrcLearnedDesync || v.Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("cached verdict = %s %q, want SrcLearnedDesync tlsfrag:pos=snimid", v.Source, v.Spec)
	}
	if st := h.srv.Stats(); st.CONNECT != 1 || st.Escalated != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

// A fragile origin — the shape MEASUREMENTS.md §5.1 measured on every Turkish
// bank — must succeed on attempt one and never be reframed.
func TestCONNECTNeverDesyncsAnOriginThatWorksPlain(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.Fragile(), "www.yapikredi.com.tr")
	d := newMapDialer()
	d.add("www.yapikredi.com.tr", l.addr())
	store := openStore(t)

	h := serveTest(t, wiring{dialer: d, store: store})

	tunnel, status := h.connect(t, "www.yapikredi.com.tr:443")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if _, err := tlsThrough(t, tunnel, "www.yapikredi.com.tr",
		l.origin.ClientConfig("www.yapikredi.com.tr")); err != nil {
		t.Fatalf("a bank that works plain failed through the proxy: %v", err)
	}
	if got := len(d.calls()); got != 1 {
		t.Fatalf("%d upstream dials, want exactly 1: a fragile host was escalated: %v", got, d.calls())
	}
	v := verdictOf(t, store, "www.yapikredi.com.tr")
	if v.Source != policy.SrcLearnedPlain {
		t.Fatalf("cached source = %s, want SrcLearnedPlain", v.Source)
	}
	if st := h.srv.Stats(); st.Escalated != 0 {
		t.Fatalf("escalations = %d, want 0", st.Escalated)
	}
}

// A compiled-in bypass is never buffered and never judged: one dial, no ladder,
// and the ladder's own dial counter proves it.
func TestCONNECTBypassIsRelayedWithoutJudging(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.Fragile(), "isbank.com.tr")
	d := newMapDialer()
	d.add("isbank.com.tr", l.addr())

	h := serveTest(t, wiring{
		dialer: d,
		rules:  []policy.Rule{bypassRule("isbank.com.tr")},
		store:  openStore(t),
	})

	tunnel, status := h.connect(t, "isbank.com.tr:443")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if _, err := tlsThrough(t, tunnel, "isbank.com.tr", l.origin.ClientConfig("isbank.com.tr")); err != nil {
		t.Fatalf("bypassed host failed: %v", err)
	}
	if got := len(d.calls()); got != 1 {
		t.Fatalf("%d dials, want 1", got)
	}
	// Nothing may be learned about a host we never judged: a bypass verdict
	// that decayed into a learned one would be a bypass that expires.
	if _, ok := h.store.Get(policy.NetworkID{}, "isbank.com.tr"); ok {
		t.Fatal("a bypassed host had a verdict written for it")
	}
}

// A server-first protocol must reach the client immediately with nothing
// buffered. Making SMTP wait for a client message that is never coming is a
// deadlock, and it is what the previous implementation shipped.
func TestCONNECTServerFirstGreetingArrivesWithNothingBuffered(t *testing.T) {
	t.Parallel()
	const greeting = "220 mail.example.com ESMTP ready\r\n"
	o := newGreetOrigin(t, greeting)
	d := newMapDialer()
	d.add("mail.example.com", o.ln.Addr())

	h := serveTest(t, wiring{dialer: d, inspect: []int{443, 80, 25}})

	tunnel, status := h.connect(t, "mail.example.com:25")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	buf := make([]byte, len(greeting))
	if _, err := io.ReadFull(tunnel, buf); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if string(buf) != greeting {
		t.Fatalf("greeting = %q", buf)
	}
}

// A dial failure before the tunnel is acknowledged is a 502 the browser can
// render, and the body says which of the three possible things is broken.
func TestCONNECTDialFailureIsARenderable502(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{
		dialer: deadDialer{err: io.ErrUnexpectedEOF},
		rules:  []policy.Rule{bypassRule("unreachable.test")},
	})

	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "CONNECT unreachable.test:443 HTTP/1.1\r\nHost: unreachable.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "no TCP connection") {
		t.Fatalf("502 body says nothing actionable: %q", body)
	}
}

// A judged flow cannot be told about a dial failure in the proxy protocol,
// because the 200 has to go out before the ClientHello can be read. What it
// must NOT do is fall back to relaying the connection plain and unbypassed: the
// tunnel is closed instead. docs/PLAN.md data path A step 12.
func TestCONNECTExhaustedLadderClosesRatherThanFallingBack(t *testing.T) {
	t.Parallel()
	// An address-level block: no payload transformation can help, so every rung
	// of the ladder fails. It is docs/PLAN.md's ShapeIPBlock, and it is the case
	// where falling back to "send it plain and call it success" would be most
	// tempting and most wrong.
	l := newLab(t, testcensor.IPBlock(netip.MustParsePrefix("127.0.0.0/8")), "discord.com")
	d := newMapDialer()
	d.add("discord.com", l.addr())
	store := openStore(t)

	h := serveTest(t, wiring{dialer: d, store: store})

	tunnel, status := h.connect(t, "discord.com:443")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if _, err := tlsThrough(t, tunnel, "discord.com", l.origin.ClientConfig("discord.com")); err == nil {
		t.Fatal("the handshake succeeded against a censor that resets everything")
	}
	if got := len(d.calls()); got < 2 {
		t.Fatalf("%d dials, want the ladder to have been walked: %v", got, d.calls())
	}
	// Nothing may be cached from a walk where every rung failed.
	if v, ok := store.Get(policy.NetworkID{}, "discord.com"); ok && v.Class == policy.ScopeDesync {
		t.Fatalf("a failed walk cached a winner: %+v", v)
	}
	if st := h.srv.Stats(); st.Failed == 0 {
		t.Fatalf("a fully failed flow was not counted as failed: %+v", st)
	}
}

// The resolver pre-flight is what turns "this name does not resolve" into a
// renderable 502 for a judged flow, despite the 200 having to come first.
func TestCONNECTResolveFailureIsA502BeforeTheAcknowledgement(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{
		resolve: failingResolve,
		dialer:  newMapDialer(),
	})

	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestCONNECTRejectsAMalformedAuthority(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	for _, authority := range []string{"discord.com:0", "discord.com:notaport", ":443"} {
		c := h.dialProxy(t)
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%s: read response: %v", authority, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", authority, resp.StatusCode)
		}
	}
}
