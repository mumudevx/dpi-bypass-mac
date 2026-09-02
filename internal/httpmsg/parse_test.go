package httpmsg

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		host      string
		complete  bool
		headerEnd int
	}{
		{
			name:      "get with host",
			in:        "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
			host:      "example.com",
			complete:  true,
			headerEnd: len("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "host with port",
			in:       "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
			host:     "example.com",
			complete: true,
		},
		{
			name:     "ipv6 literal keeps its brackets",
			in:       "GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n",
			host:     "[2001:db8::1]",
			complete: true,
		},
		{
			name:     "ipv6 literal without a port",
			in:       "GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n",
			host:     "[2001:db8::1]",
			complete: true,
		},
		{
			name:     "unterminated ipv6 bracket is taken whole",
			in:       "GET / HTTP/1.1\r\nHost: [2001:db8::1\r\n\r\n",
			host:     "[2001:db8::1",
			complete: true,
		},
		{
			name:     "value is trimmed of OWS",
			in:       "GET / HTTP/1.1\r\nHost:  \texample.com \t\r\n\r\n",
			host:     "example.com",
			complete: true,
		},
		{
			name:     "header name case is irrelevant",
			in:       "GET / HTTP/1.1\r\nhOSt: example.com\r\n\r\n",
			host:     "example.com",
			complete: true,
		},
		{
			name:     "bare LF line endings",
			in:       "GET / HTTP/1.1\nHost: example.com\n\n",
			host:     "example.com",
			complete: true,
		},
		{
			name:     "absolute-form target",
			in:       "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
			host:     "example.com",
			complete: true,
		},
		{
			name:     "first Host header wins",
			in:       "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
			host:     "a.example",
			complete: true,
		},
		{
			name:     "no host header",
			in:       "GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n",
			host:     "",
			complete: true,
		},
		{
			name:     "header block not terminated",
			in:       "GET / HTTP/1.1\r\nHost: example.com\r\n",
			host:     "example.com",
			complete: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Parse([]byte(c.in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if r.Complete != c.complete {
				t.Errorf("Complete = %v, want %v", r.Complete, c.complete)
			}
			if r.HasHost() != (c.host != "") {
				t.Fatalf("HasHost = %v, want %v", r.HasHost(), c.host != "")
			}
			if c.host == "" {
				if r.HostStart != -1 || r.HostEnd != -1 {
					t.Errorf("absent host is not -1/-1: %d/%d", r.HostStart, r.HostEnd)
				}
				return
			}
			if r.Host != c.host {
				t.Errorf("Host = %q, want %q", r.Host, c.host)
			}
			if got := c.in[r.HostStart:r.HostEnd]; got != c.host {
				t.Errorf("offsets address %q, want %q", got, c.host)
			}
			if got := strings.ToLower(c.in[r.NameStart:r.NameEnd]); got != "host" {
				t.Errorf("name offsets address %q", got)
			}
			if r.ValueEnd < r.HostEnd {
				t.Errorf("value [%d,%d) does not contain host [%d,%d)",
					r.ValueStart, r.ValueEnd, r.HostStart, r.HostEnd)
			}
			if c.headerEnd != 0 && r.HeaderEnd != c.headerEnd {
				t.Errorf("HeaderEnd = %d, want %d", r.HeaderEnd, c.headerEnd)
			}
		})
	}
}

// TestParseIsHeaderBlockScoped is DOSSIER.md's P2 note encoded: the previous
// implementation searched the whole payload for the Host header, so a request
// body carrying "Host:" moved the mangling offsets onto application data.
func TestParseIsHeaderBlockScoped(t *testing.T) {
	in := "POST / HTTP/1.1\r\nContent-Length: 24\r\n\r\nHost: attacker.example\r\n"
	r, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.HasHost() {
		t.Fatalf("found a Host header in the body: %q at [%d,%d)", r.Host, r.HostStart, r.HostEnd)
	}
	if r.HeaderEnd != strings.Index(in, "\r\n\r\n")+4 {
		t.Errorf("HeaderEnd = %d", r.HeaderEnd)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown method":     "FROB / HTTP/1.1\r\n\r\n",
		"method not spaced":  "GETX / HTTP/1.1\r\n\r\n",
		"no version":         "GET /\r\n\r\n",
		"http/2 preface":     "PRI * HTTP/2.0\r\n\r\n",
		"http/0.9":           "GET /\r\n",
		"binary":             "\x16\x03\x01\x00\x05\r\n",
		"request line only":  "GET / HTTP/1.1",
		"empty":              "",
		"leading space":      " GET / HTTP/1.1\r\n\r\n",
		"bad version digit":  "GET / HTTP/1.x\r\n\r\n",
		"target-less":        "GET  HTTP/1.1\r\n\r\n",
		"trailing-space-ver": "GET / HTTP/1.1 \r\n\r\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); !errors.Is(err, ErrNotRequest) {
				t.Fatalf("err = %v, want ErrNotRequest", err)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	yes := []string{"G", "GE", "GET", "GET ", "GET / HTTP/1.1\r\n", "CONNECT a:443 HTTP/1.1\r\n", "P", "PO", "OPTIONS *"}
	no := []string{"", "GETX", "x", "\x16\x03\x01", "ge", "PRIX"}
	for _, s := range yes {
		if !Detect([]byte(s)) {
			t.Errorf("Detect(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if Detect([]byte(s)) {
			t.Errorf("Detect(%q) = true, want false", s)
		}
	}
}

func TestNeed(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"GET / HTTP/1.1\r\n\r\n", 0, true},
		{"GET / HTTP/1.1\r\nHost: a\r\n\r\n", 0, true},
		{"GET / HTTP/1.1\r\nHost: a\r\n", 1, true},
		{"GET ", 1, true},
		{"GE", 1, true},
		{"FROB / HTTP/1.1\r\n\r\n", 0, false},
		{"GET /\r\n\r\n", 0, false},
		{"\x00", 0, false},
	}
	for _, c := range cases {
		got, ok := Need([]byte(c.in))
		if got != c.want || ok != c.ok {
			t.Errorf("Need(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseHeadOverMaxHead(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	for sb.Len() < MaxHead {
		sb.WriteString("X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
	}
	sb.WriteString("Host: example.com\r\n\r\n")

	r, err := Parse([]byte(sb.String()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Complete {
		t.Fatal("a head larger than MaxHead must not be reported complete")
	}
	if r.HasHost() {
		t.Fatal("a Host beyond MaxHead must not be located")
	}
}
