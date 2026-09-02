package httpmsg

import (
	"strings"
	"testing"
)

func seeds(f *testing.F) []string {
	f.Helper()
	return []string{
		req,
		"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
		"POST /x HTTP/1.0\r\nHost: [::1]:443\r\nContent-Length: 3\r\n\r\nabc",
		"HEAD / HTTP/1.1\nHost: a\n\n",
		"GET / HTTP/1.1\r\nHost:\r\n\r\n",
		"CONNECT a.example:443 HTTP/1.1\r\n\r\n",
		"GET",
		"\x16\x03\x01\x00\x05",
		"",
	}
}

// FuzzParseHTTPHost asserts that every offset Parse reports is inside the buffer
// and inside the header block. The mutators index the payload with these
// offsets, so an offset that escapes here is an out-of-range write on a request
// an application controls.
func FuzzParseHTTPHost(f *testing.F) {
	for _, s := range seeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b := []byte(s)
		r, err := Parse(b)
		if err != nil {
			if r.HasHost() {
				t.Fatal("a failed parse reported a host")
			}
			return
		}
		if r.Complete {
			if r.HeaderEnd < 0 || r.HeaderEnd > len(b) {
				t.Fatalf("HeaderEnd %d escapes a %d-byte buffer", r.HeaderEnd, len(b))
			}
		} else if r.HeaderEnd != -1 {
			t.Fatalf("HeaderEnd %d set on an incomplete head", r.HeaderEnd)
		}
		if !r.HasHost() {
			return
		}
		for _, e := range [][2]int{
			{r.NameStart, r.NameEnd}, {r.ValueStart, r.ValueEnd}, {r.HostStart, r.HostEnd},
		} {
			if e[0] < 0 || e[1] < e[0] || e[1] > len(b) {
				t.Fatalf("extent [%d,%d) escapes a %d-byte buffer", e[0], e[1], len(b))
			}
		}
		if r.Complete && r.ValueEnd > r.HeaderEnd {
			t.Fatalf("value [%d,%d) escapes the header block (%d)", r.ValueStart, r.ValueEnd, r.HeaderEnd)
		}
		if r.HostStart < r.ValueStart || r.HostEnd > r.ValueEnd {
			t.Fatalf("host [%d,%d) escapes the value [%d,%d)", r.HostStart, r.HostEnd, r.ValueStart, r.ValueEnd)
		}
		if string(b[r.HostStart:r.HostEnd]) != r.Host {
			t.Fatalf("offsets address %q, Host is %q", b[r.HostStart:r.HostEnd], r.Host)
		}
		if !strings.EqualFold(string(b[r.NameStart:r.NameEnd]), "host") {
			t.Fatalf("name offsets address %q", b[r.NameStart:r.NameEnd])
		}
	})
}

// FuzzMangleKeepsRequestParseable asserts every mutator's output is still a
// request head naming the same host. A mutator that corrupts the request is
// strictly worse than no mutator: MEASUREMENTS.md §5.1 already shows that
// whatever confuses a DPI parser confuses fragile origins too.
func FuzzMangleKeepsRequestParseable(f *testing.F) {
	for _, s := range seeds(f) {
		f.Add(s, 32)
	}
	f.Fuzz(func(t *testing.T, s string, pad int) {
		b := []byte(s)
		before, beforeErr := Parse(b)

		outs := map[string][]byte{}
		if o, err := HostCase(b); err == nil {
			outs["hostcase"] = o
		}
		if o, err := HostDot(b); err == nil {
			outs["hostdot"] = o
		}
		if o, err := HostPad(b, pad); err == nil {
			outs["hostpad"] = o
		}
		if len(outs) > 0 && (beforeErr != nil || !before.HasHost() || !before.Complete) {
			t.Fatalf("a mutator accepted a head Parse calls err=%v host=%v complete=%v",
				beforeErr, before.HasHost(), before.Complete)
		}
		for name, out := range outs {
			after, err := Parse(out)
			if err != nil {
				t.Fatalf("%s produced an unparseable head: %v", name, err)
			}
			if !after.Complete || !after.HasHost() {
				t.Fatalf("%s lost the header block or the host", name)
			}
			want := before.Host
			if name == "hostdot" {
				want += "."
			}
			if after.Host != want {
				t.Fatalf("%s changed the host from %q to %q", name, want, after.Host)
			}
		}
	})
}
