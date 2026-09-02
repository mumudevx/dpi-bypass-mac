package httpmsg

import (
	"strings"
	"testing"
)

// TestReplayable pins the plaintext half of the retry model. MEASUREMENTS.md §5.2
// argues retry is transparent for TLS because the ClientHello is the first thing
// on the wire; plaintext HTTP has no such guarantee, so anything that could
// duplicate a side effect or truncate a body must be refused.
func TestReplayable(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"GET", "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", true},
		{"HEAD", "HEAD / HTTP/1.1\r\nHost: a.example\r\n\r\n", true},
		{"PUT with no body", "PUT /x HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n", true},
		{"DELETE", "DELETE /x HTTP/1.1\r\nHost: a.example\r\n\r\n", true},
		{"OPTIONS", "OPTIONS * HTTP/1.1\r\nHost: a.example\r\n\r\n", true},
		{"no Host header", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", true},

		{"POST", "POST /x HTTP/1.1\r\nHost: a.example\r\n\r\n", false},
		{"PATCH", "PATCH /x HTTP/1.1\r\nHost: a.example\r\n\r\n", false},
		{"CONNECT", "CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n", false},
		{"body bytes buffered", "GET / HTTP/1.1\r\nHost: a.example\r\n\r\nx", false},
		{"pipelined second request", "GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n", false},
		{"content-length", "PUT / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n", false},
		{"malformed content-length", "PUT / HTTP/1.1\r\nHost: a\r\nContent-Length: x\r\n\r\n", false},
		{"chunked", "PUT / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", false},
		{"expect continue", "PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n", false},
		{"upgrade header", "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n", false},
		{"connection upgrade", "GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\n\r\n", false},
		{"incomplete head", "GET / HTTP/1.1\r\nHost: a\r\n", false},
		{"not a request", "\x16\x03\x01\x00\x05\r\n\r\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := ReplayableReason([]byte(c.in))
			if got != c.want {
				t.Fatalf("Replayable = %v (%s), want %v", got, reason, c.want)
			}
			if got != Replayable([]byte(c.in)) {
				t.Fatal("Replayable disagrees with ReplayableReason")
			}
			if !got && reason == "" {
				t.Fatal("a refusal with no reason is unattributable in a log line")
			}
			if got && reason != "" {
				t.Fatalf("an acceptance carries a reason: %q", reason)
			}
		})
	}
}

// TestReplayableIgnoresTheBody pins that a "Transfer-Encoding" line appearing
// after the header block cannot flip the decision, in either direction.
func TestReplayableIgnoresTheBody(t *testing.T) {
	// The body is what makes this unreplayable, not its content.
	in := "GET / HTTP/1.1\r\nHost: a\r\n\r\nTransfer-Encoding: chunked\r\n"
	ok, reason := ReplayableReason([]byte(in))
	if ok {
		t.Fatal("replayable despite buffered body bytes")
	}
	if !strings.Contains(reason, "follow the header block") {
		t.Fatalf("reason = %q, want the body-bytes reason rather than a body-parsed one", reason)
	}
}

func TestIsZeroLength(t *testing.T) {
	cases := map[string]bool{"0": true, "00": true, "": false, "1": false, "0x": false, " 0": false}
	for in, want := range cases {
		if got := isZeroLength([]byte(in)); got != want {
			t.Errorf("isZeroLength(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestContainsToken(t *testing.T) {
	cases := []struct {
		v    string
		tok  string
		want bool
	}{
		{"upgrade", "upgrade", true},
		{"keep-alive, Upgrade", "upgrade", true},
		{"Upgrade,close", "upgrade", true},
		{" \tupgrade\t ", "upgrade", true},
		{"keep-alive", "upgrade", false},
		{"upgraded", "upgrade", false},
		{"", "upgrade", false},
	}
	for _, c := range cases {
		if got := containsToken([]byte(c.v), c.tok); got != c.want {
			t.Errorf("containsToken(%q,%q) = %v, want %v", c.v, c.tok, got, c.want)
		}
	}
}
