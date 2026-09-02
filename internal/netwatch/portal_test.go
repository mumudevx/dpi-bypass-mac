package netwatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
)

// fakeDialer answers a flow.Target by name with a scripted HTTP response over
// net.Pipe. No socket is bound and no packet leaves the process.
type fakeDialer struct {
	reply map[string]string // host -> raw response bytes
	fail  map[string]error
	seen  []string
}

func (d *fakeDialer) DialTCP(ctx context.Context, t flow.Target) (net.Conn, error) {
	d.seen = append(d.seen, t.Name)
	if err := d.fail[t.Name]; err != nil {
		return nil, err
	}
	raw, ok := d.reply[t.Name]
	if !ok {
		return nil, fmt.Errorf("no route to %s", t.Name)
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		_, _ = server.Read(buf) // the request; its content is asserted elsewhere
		_, _ = io.WriteString(server, raw)
	}()
	return client, nil
}

const (
	clean204   = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
	cleanApple = "HTTP/1.1 200 OK\r\nContent-Length: 69\r\n\r\n" +
		"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
	portal302 = "HTTP/1.1 302 Found\r\nLocation: http://portal.hotel.example/login\r\n\r\n"
	portal200 = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Please sign in</html>"
)

func canaries() []Canary {
	return []Canary{
		{Host: "a.example", Path: "/generate_204", WantStatus: 204},
		{Host: "b.example", Path: "/hotspot-detect.html", WantStatus: 200, WantBody: "success"},
		{Host: "c.example", Path: "/success.txt", WantStatus: 204},
	}
}

func TestPortalProbe(t *testing.T) {
	cases := []struct {
		name       string
		reply      map[string]string
		fail       map[string]error
		resolve    flow.ResolveFunc
		wantBehind bool
		wantErr    bool
		wantDetail string
		wantLogin  string
	}{
		{
			name: "a clean network is not behind a portal",
			reply: map[string]string{
				"a.example": clean204, "b.example": cleanApple, "c.example": clean204,
			},
		},
		{
			name: "one clean canary refutes a portal even when the others are intercepted",
			reply: map[string]string{
				"a.example": clean204, "b.example": portal302, "c.example": portal302,
			},
		},
		{
			name: "two intercepted canaries and no clean one is a portal",
			reply: map[string]string{
				"a.example": portal302, "b.example": portal302,
			},
			fail:       map[string]error{"c.example": errors.New("connection refused")},
			wantBehind: true,
			wantLogin:  "http://portal.hotel.example/login",
			wantDetail: "302",
		},
		{
			// The shape that matters most: a portal that answers 200 with its
			// own page at an endpoint whose clean answer is a 200. A status
			// check alone would call this clean.
			name: "a 200 whose body is the login page is interception",
			reply: map[string]string{
				"b.example": portal200, "a.example": portal200, "c.example": portal200,
			},
			wantBehind: true,
			wantDetail: "instead of the expected 204",
		},
		{
			// A censored canary must not be able to suspend dpb on its own.
			// This is the failure that would disable the bypass exactly where
			// it is needed.
			name:  "one intercepted canary alone is inconclusive, never a portal",
			reply: map[string]string{"a.example": portal302},
			fail: map[string]error{
				"b.example": errors.New("i/o timeout"),
				"c.example": errors.New("i/o timeout"),
			},
			wantErr: true,
		},
		{
			// ...unless DNS also says the whole namespace collapsed onto one
			// address, which is what an intercepting gateway looks like.
			name:  "one intercepted canary plus DNS uniformity is a portal",
			reply: map[string]string{"a.example": portal302},
			fail: map[string]error{
				"b.example": errors.New("i/o timeout"),
				"c.example": errors.New("i/o timeout"),
			},
			resolve: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.168.1.1")}, nil
			},
			wantBehind: true,
			wantDetail: "distinct blocked names",
		},
		{
			// A dead network is not a portal. Suspending here would mean dpb
			// switched itself off every time a user walked out of range.
			name: "a network nothing answers on is inconclusive",
			fail: map[string]error{
				"a.example": errors.New("no route to host"),
				"b.example": errors.New("no route to host"),
				"c.example": errors.New("no route to host"),
			},
			wantErr: true,
		},
		{
			name:    "a peer that does not speak HTTP is an error, not a verdict",
			reply:   map[string]string{"a.example": "\x16\x03\x01 not http at all\r\n\r\n"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDialer{reply: tc.reply, fail: tc.fail}
			p := &PortalProbe{Dial: d, Canaries: canaries(), Resolve: tc.resolve}
			got := p.Probe(context.Background())

			if got.Behind != tc.wantBehind {
				t.Fatalf("Behind = %v (%s / %v), want %v", got.Behind, got.Detail, got.Err, tc.wantBehind)
			}
			if (got.Err != nil) != tc.wantErr {
				t.Fatalf("Err = %v, want an error: %v", got.Err, tc.wantErr)
			}
			if tc.wantDetail != "" && !strings.Contains(got.Detail, tc.wantDetail) {
				t.Errorf("Detail = %q, want it to mention %q", got.Detail, tc.wantDetail)
			}
			if tc.wantLogin != "" && got.LoginURL != tc.wantLogin {
				t.Errorf("LoginURL = %q, want %q", got.LoginURL, tc.wantLogin)
			}
			if got.At.IsZero() {
				t.Error("the verdict carries no timestamp")
			}
		})
	}
}

// TestPortalProbeSendsARealRequest pins the request line and Host header: a
// portal keys on the path, and a canary asking for the wrong one is answered
// correctly by a portal and mis-scored as clean.
func TestPortalProbeSendsARealRequest(t *testing.T) {
	got := make(chan string, 1)
	d := dialerFunc(func(ctx context.Context, tg flow.Target) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1024)
			n, _ := server.Read(buf)
			got <- string(buf[:n])
			_, _ = io.WriteString(server, clean204)
		}()
		return client, nil
	})
	p := &PortalProbe{
		Dial:     d,
		Canaries: []Canary{{Host: "a.example", Path: "/generate_204", WantStatus: 204}},
	}
	if v := p.Probe(context.Background()); v.Behind {
		t.Fatalf("a clean 204 was scored as a portal: %s", v.Detail)
	}
	req := <-got
	for _, want := range []string{
		"GET /generate_204 HTTP/1.1\r\n",
		"Host: a.example\r\n",
		"Cache-Control: no-cache\r\n",
		"Connection: close\r\n",
	} {
		if !strings.Contains(req, want) {
			t.Errorf("the canary request does not contain %q:\n%s", want, req)
		}
	}
}

// TestPortalProbeCatchesA200WithTheWrongBody is the shape a status-code check
// alone calls clean: the endpoint's clean answer IS a 200, and only the fixed
// word in the body tells the origin's answer from the portal's.
func TestPortalProbeCatchesA200WithTheWrongBody(t *testing.T) {
	d := &fakeDialer{reply: map[string]string{"b.example": portal200, "d.example": portal200}}
	p := &PortalProbe{Dial: d, Canaries: []Canary{
		{Host: "b.example", Path: "/hotspot-detect.html", WantStatus: 200, WantBody: "success"},
		{Host: "d.example", Path: "/success.txt", WantStatus: 200, WantBody: "success"},
	}}
	v := p.Probe(context.Background())
	if !v.Behind {
		t.Fatalf("a 200 carrying a login page was scored clean: %+v", v)
	}
	if !strings.Contains(v.Detail, "does not say") {
		t.Fatalf("Detail = %q, want it to say the body was wrong", v.Detail)
	}
}

type dialerFunc func(context.Context, flow.Target) (net.Conn, error)

func (f dialerFunc) DialTCP(ctx context.Context, t flow.Target) (net.Conn, error) { return f(ctx, t) }

func TestPortalProbeWithoutADialerRefusesRatherThanGuessing(t *testing.T) {
	var p PortalProbe
	v := p.Probe(context.Background())
	if v.Behind || v.Err == nil {
		t.Fatalf("a probe with no dialer returned %+v", v)
	}
}

func TestPortalProbeStopsWhenTheContextIsDone(t *testing.T) {
	d := &fakeDialer{reply: map[string]string{"a.example": clean204}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &PortalProbe{Dial: d, Canaries: canaries()}
	v := p.Probe(ctx)
	if v.Behind {
		t.Fatal("a cancelled probe declared a portal")
	}
	if len(d.seen) != 0 {
		t.Fatalf("a cancelled probe still dialled %v", d.seen)
	}
}

// TestPortalProbeDefaultsToTheOSCanaries pins that a zero-valued probe uses
// the shipped endpoints rather than probing nothing, and that none of them is
// a host this tool exists to unblock — a censored canary would suspend dpb on
// exactly the networks it is for.
func TestPortalProbeDefaultsToTheOSCanaries(t *testing.T) {
	var p PortalProbe
	cs := p.canaries()
	if len(cs) != len(DefaultCanaries) {
		t.Fatalf("canaries() returned %d, want the %d defaults", len(cs), len(DefaultCanaries))
	}
	for _, c := range cs {
		if c.WantStatus == 0 {
			t.Errorf("canary %s has no expected status, so nothing can be compared", c.Host)
		}
		for _, blocked := range []string{"discord", "wikipedia", "onlyfans", "roblox"} {
			if strings.Contains(c.Host, blocked) {
				t.Errorf("canary %s is a censored host; a censored canary suspends dpb "+
					"on every network it is needed on", c.Host)
			}
		}
	}
}

// TestPortalProbeReusesResolvesDetector pins that the uniformity heuristic is
// resolve's, not a second copy of it: two implementations of a quorum rule
// mean two places to get the quorum wrong.
func TestPortalProbeReusesResolvesDetector(t *testing.T) {
	det := resolve.NewDetector(nil, []string{"a.example", "b.example", "c.example"})
	p := &PortalProbe{Dial: &fakeDialer{}, Detector: det}
	if p.detector(canaries()) != det {
		t.Fatal("an explicitly configured detector was ignored")
	}
	// The built-in one must learn from the canary names, which are not
	// resolve's DefaultPoisonProbes.
	built := (&PortalProbe{}).detector(canaries())
	one := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	for _, c := range canaries() {
		built.Learn(c.Host, one)
	}
	if sig := built.Check("a.example", one); !sig.Poisoned || !sig.Uniform {
		t.Fatalf("three canary names on one address did not reach the quorum: %+v", sig)
	}
}

func TestReadResponse(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantStatus int
		wantErr    bool
		wantBody   string
	}{
		{name: "204", raw: clean204, wantStatus: 204},
		{name: "302 with a location", raw: portal302, wantStatus: 302},
		{name: "200 with a body", raw: cleanApple, wantStatus: 200, wantBody: "Success"},
		{name: "empty", raw: "", wantErr: true},
		{name: "not http", raw: "hello\r\n", wantErr: true},
		{name: "unparseable status", raw: "HTTP/1.1 two hundred\r\n\r\n", wantErr: true},
		{name: "status line only", raw: "HTTP/1.0 204 No Content\r\n", wantStatus: 204},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, hdr, body, err := readResponse(strings.NewReader(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want an error: %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if tc.wantBody != "" && !strings.Contains(body, tc.wantBody) {
				t.Errorf("body = %q, want it to contain %q", body, tc.wantBody)
			}
			if tc.wantStatus == 302 && hdr.Get("Location") == "" {
				t.Error("the Location header was dropped, so the user is never told where to log in")
			}
		})
	}
}

// TestReadResponseIsBounded pins that a portal serving an endless body cannot
// make the probe allocate without limit.
func TestReadResponseIsBounded(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("x", 1<<20)
	_, _, body, err := readResponse(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if len(body) > portalBodyCap {
		t.Fatalf("read %d bytes of body, cap is %d", len(body), portalBodyCap)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abc", 5); got != "abc" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc…" {
		t.Errorf("truncate long = %q", got)
	}
}

func TestHostHeader(t *testing.T) {
	if got := hostHeader("a.example", 80); got != "a.example" {
		t.Errorf("port 80 host header = %q, want the bare name", got)
	}
	if got := hostHeader("a.example", 8080); got != "a.example:8080" {
		t.Errorf("port 8080 host header = %q", got)
	}
}

func TestLoginSuffix(t *testing.T) {
	if loginSuffix("") != "" {
		t.Error("an empty location produced a suffix")
	}
	if !strings.Contains(loginSuffix("http://x/"), "http://x/") {
		t.Error("the location was dropped from the suffix")
	}
}
