package proxyfe_test

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

func readBody(t *testing.T, br *bufio.Reader, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// THE regression this file exists for.
//
// The previous implementation dialled one upstream for the first request's host
// and then tunnelled the rest of the client connection into it, so request two
// addressed to backend B was delivered to backend A. Two pipelined requests to
// two origins must reach two origins.
func TestPipelinedPlaintextRequestsReachDifferentBackends(t *testing.T) {
	t.Parallel()
	a := newHTTPOrigin(t, "alpha")
	b := newHTTPOrigin(t, "bravo")
	d := newMapDialer()
	d.add("a.test", a.addr())
	d.add("b.test", b.addr())

	h := serveTest(t, wiring{dialer: d, store: openStore(t)})

	c := h.dialProxy(t)
	// Both requests are written before either response is read: pipelined, the
	// shape that makes a pooled-connection bug visible.
	if _, err := io.WriteString(c,
		"GET http://a.test/one HTTP/1.1\r\nHost: a.test\r\n\r\n"+
			"GET http://b.test/two HTTP/1.1\r\nHost: b.test\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	br := bufio.NewReader(c)
	_, first := readBody(t, br, nil)
	_, second := readBody(t, br, nil)

	if !strings.Contains(first, "alpha answered /one") {
		t.Fatalf("request 1 answered by %q, want alpha", first)
	}
	if !strings.Contains(second, "bravo answered /two") {
		t.Fatalf("request 2 answered by %q, want bravo: the second request was delivered "+
			"to the first request's backend", second)
	}
	if got := a.seen(); len(got) != 1 || got[0] != "a.test/one|" {
		t.Fatalf("alpha saw %v", got)
	}
	if got := b.seen(); len(got) != 1 || got[0] != "b.test/two|" {
		t.Fatalf("bravo saw %v", got)
	}
	if calls := d.calls(); len(calls) != 2 {
		t.Fatalf("dials = %v, want one per request", calls)
	}
}

// Every request gets its own upstream even when both go to the same origin:
// there is no pool, so there is nothing for a later request to inherit.
func TestEachPlaintextRequestDialsItsOwnUpstream(t *testing.T) {
	t.Parallel()
	a := newHTTPOrigin(t, "alpha")
	d := newMapDialer()
	d.add("a.test", a.addr())

	h := serveTest(t, wiring{dialer: d, store: openStore(t)})
	c := h.dialProxy(t)
	br := bufio.NewReader(c)
	for i := 0; i < 3; i++ {
		fmt.Fprintf(c, "GET http://a.test/%d HTTP/1.1\r\nHost: a.test\r\n\r\n", i)
		resp, body := readBody(t, br, nil)
		if resp.StatusCode != 200 || !strings.Contains(body, fmt.Sprintf("/%d", i)) {
			t.Fatalf("request %d: %d %q", i, resp.StatusCode, body)
		}
	}
	if got := a.connections(); got != 3 {
		t.Fatalf("origin accepted %d connections, want one per request", got)
	}
}

// The head the origin receives must be origin-form and must have lost the
// proxy's own hop-by-hop headers.
func TestForwardedRequestIsOriginFormWithoutHopByHopHeaders(t *testing.T) {
	t.Parallel()
	a := newHTTPOrigin(t, "alpha")
	d := newMapDialer()
	d.add("a.test", a.addr())
	h := serveTest(t, wiring{dialer: d, store: openStore(t)})

	c := h.dialProxy(t)
	if _, err := io.WriteString(c,
		"GET http://a.test/path?q=1 HTTP/1.1\r\n"+
			"Host: a.test\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"+
			"Connection: keep-alive, X-Secret\r\n"+
			"X-Secret: gone\r\n"+
			"X-Kept: here\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	resp, _ := readBody(t, br, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := a.seen(); len(got) != 1 || got[0] != "a.test/path?q=1|" {
		t.Fatalf("origin saw %v, want the origin-form target with its query intact", got)
	}
}

// A POST is forwarded body and all, and — because it is not replayable — it is
// never retried on a censored line. Replaying it would submit it twice and the
// user would never know.
func TestPlaintextPOSTIsForwardedOnceAndNeverRetried(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.IPBlock(netip.MustParsePrefix("127.0.0.0/8")), "a.test")
	d := newMapDialer()
	d.add("a.test", l.addr())
	h := serveTest(t, wiring{dialer: d, store: openStore(t)})

	c := h.dialProxy(t)
	body := "order=1"
	fmt.Fprintf(c, "POST http://a.test/checkout HTTP/1.1\r\nHost: a.test\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(body), body)
	resp, _ := readBody(t, bufio.NewReader(c), nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := len(d.calls()); got != 1 {
		t.Fatalf("%d upstream dials for a POST, want exactly 1: a non-idempotent request was replayed", got)
	}
}

func TestPlaintextPOSTBodyReachesTheOrigin(t *testing.T) {
	t.Parallel()
	a := newHTTPOrigin(t, "alpha")
	d := newMapDialer()
	d.add("a.test", a.addr())
	h := serveTest(t, wiring{dialer: d, store: openStore(t)})

	c := h.dialProxy(t)
	body := "name=value"
	fmt.Fprintf(c, "POST http://a.test/submit HTTP/1.1\r\nHost: a.test\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(body), body)
	resp, _ := readBody(t, bufio.NewReader(c), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := a.seen(); len(got) != 1 || got[0] != "a.test/submit|name=value" {
		t.Fatalf("origin saw %v, want the body forwarded", got)
	}
}

// A chunked request body must arrive re-chunked. Go's parser decodes the
// framing, so forwarding req.Body raw would silently strip it and the origin
// would read a body it has no length for.
func TestChunkedRequestBodyIsReframed(t *testing.T) {
	t.Parallel()
	a := newHTTPOrigin(t, "alpha")
	d := newMapDialer()
	d.add("a.test", a.addr())
	h := serveTest(t, wiring{dialer: d, store: openStore(t)})

	c := h.dialProxy(t)
	if _, err := io.WriteString(c,
		"POST http://a.test/stream HTTP/1.1\r\nHost: a.test\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n"+
			"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, _ := readBody(t, bufio.NewReader(c), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := a.seen(); len(got) != 1 || got[0] != "a.test/stream|hello world" {
		t.Fatalf("origin saw %v, want the chunked body reassembled to \"hello world\"", got)
	}
}

// A plaintext request to a bypassed host is relayed without ever entering the
// ladder, exactly like a bypassed CONNECT.
func TestPlaintextBypassSkipsTheLadder(t *testing.T) {
	t.Parallel()
	a := newHTTPOrigin(t, "alpha")
	d := newMapDialer()
	d.add("gib.gov.tr", a.addr())
	h := serveTest(t, wiring{
		dialer: d,
		rules:  []policy.Rule{bypassRule("gib.gov.tr")},
		store:  openStore(t),
	})

	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "GET http://gib.gov.tr/ HTTP/1.1\r\nHost: gib.gov.tr\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, body := readBody(t, bufio.NewReader(c), nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "alpha") {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if _, ok := h.store.Get(policy.NetworkID{}, "gib.gov.tr"); ok {
		t.Fatal("a bypassed host had a verdict written for it")
	}
}

func TestNonHTTPSchemeIsRefused(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "GET https://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, body := readBody(t, bufio.NewReader(c), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(body, "CONNECT") {
		t.Fatalf("400 body says nothing actionable: %q", body)
	}
}

func TestMalformedRequestLineGets400(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "GET\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, _ := readBody(t, bufio.NewReader(c), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRequestWithNoHostIsRefused(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	c := h.dialProxy(t)
	// HTTP/1.0 absolute-form with no Host header at all.
	if _, err := io.WriteString(c, "GET http:/// HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, _ := readBody(t, bufio.NewReader(c), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
