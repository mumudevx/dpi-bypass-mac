package testcensor

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// clientHello captures a genuine ClientHello for name from crypto/tls.
//
// A hand-built hello would be a second implementation of the thing under test;
// capturing the real one means the record layout, the extension order and the
// post-quantum key share are whatever the Go version actually emits, which is
// what the emitters will meet in production.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go func() {
		c := tls.Client(cli, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
		_ = c.Handshake()
		_ = c.Close()
	}()

	if err := srv.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := srv.Read(tmp)
		if err != nil {
			t.Fatalf("read ClientHello: %v", err)
		}
		buf = append(buf, tmp[:n]...)
		want, ok := tlsmsg.Need(buf, tlsmsg.ProtoTLS)
		if !ok {
			t.Fatalf("captured %d bytes that are not a TLS record", len(buf))
		}
		if want == 0 {
			return buf
		}
	}
}

// sniExtent returns the body-relative extent of the hostname in a hello.
func sniExtent(t *testing.T, hello []byte) (start, end int) {
	t.Helper()
	m := tlsmsg.Parse(hello, 443)
	if !m.HasSNI() {
		t.Fatalf("captured hello has no SNI")
	}
	return m.SNIStart, m.SNIEnd
}

// split reframes hello into two records cut at the body-relative offset.
func split(t *testing.T, hello []byte, cut int) []byte {
	t.Helper()
	out, err := tlsmsg.SplitRecord(hello, []int{cut})
	if err != nil {
		t.Fatalf("SplitRecord(cut=%d): %v", cut, err)
	}
	return out
}

// feed drives an inspector with one or more client segments and returns the
// final verdict.
func feed(m Model, segs ...[]byte) Verdict {
	in := m.Inspect(443)
	var v Verdict
	for _, s := range segs {
		v, _ = in.Client(s, 0)
	}
	return v
}
