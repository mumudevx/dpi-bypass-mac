package cliapp

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// censorLab is a censored line on loopback.
//
// `dpb probe` dials a real socket at a real address, so exercising the shipped
// command end to end needs the model in front of a real listener rather than in
// a dialler. This is that listener: it accepts, routes the flow through
// testcensor.Middlebox, and turns the middlebox's verdict into what a client
// socket actually observes — a genuine RST via SetLinger(0), or silence.
type censorLab struct {
	origin *testcensor.Origin
	box    *testcensor.Middlebox
	ln     net.Listener
	caPath string

	wg sync.WaitGroup
}

func newCensorLab(t *testing.T, m testcensor.Model, names ...string) *censorLab {
	t.Helper()
	if len(names) == 0 {
		names = []string{"discord.com", "cloudflare.com"}
	}
	o, err := testcensor.NewOrigin(testcensor.OriginConfig{Names: names})
	if err != nil {
		t.Fatalf("origin: %v", err)
	}
	t.Cleanup(func() { o.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	l := &censorLab{
		origin: o,
		// Port 443 is asserted: the listener binds an ephemeral port, and a
		// model scoped to 443 would otherwise inspect nothing at all.
		box:    testcensor.New(m, testcensor.Options{Port: 443, Logf: t.Logf}),
		ln:     ln,
		caPath: exportOriginCA(t, o),
	}
	l.wg.Add(1)
	go l.accept(t)
	t.Cleanup(func() {
		ln.Close()
		l.wg.Wait()
	})
	return l
}

func (l *censorLab) port() int {
	return l.ln.Addr().(*net.TCPAddr).Port
}

func (l *censorLab) accept(t *testing.T) {
	defer l.wg.Done()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.wg.Add(1)
		go l.serve(t, c)
	}
}

func (l *censorLab) serve(t *testing.T, client net.Conn) {
	defer l.wg.Done()
	defer client.Close()

	up, err := l.box.DialContext(context.Background(), "tcp", l.origin.Addr())
	if err != nil {
		reset(client)
		return
	}
	defer up.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// A read error from the middlebox is its verdict arriving. Turning it
		// into a real RST on the client socket is what makes the shipped
		// classifier see ECONNRESET, which is what the live line produces.
		if _, err := io.Copy(client, up); err != nil {
			reset(client)
		}
		unblock(client)
	}()

	buf := make([]byte, 32<<10)
	for {
		n, rerr := client.Read(buf)
		if n > 0 {
			if _, werr := up.Write(buf[:n]); werr != nil {
				reset(client)
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	up.Close()
	wg.Wait()
}

func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// unblock ends the peer's read without waiting for its own close.
func unblock(c net.Conn) { _ = c.Close() }

// exportOriginCA writes the origin's self-signed certificate out as PEM so the
// probe can be run with full verification instead of --insecure. PASS has to
// keep meaning "the certificate validates for the name" in the offline test,
// or the offline test is checking something weaker than the live one.
func exportOriginCA(t *testing.T, o *testcensor.Origin) string {
	t.Helper()

	c, err := tls.Dial("tcp", o.Addr(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // fixture
	if err != nil {
		t.Fatalf("fetch the origin certificate: %v", err)
	}
	defer c.Close()

	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("the origin presented no certificate")
	}
	path := filepath.Join(t.TempDir(), "origin.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

func (l *censorLab) portArg() string { return strconv.Itoa(l.port()) }

// loopbackPrefix is every address the fixture can dial, which is what makes
// testcensor.IPBlock model an address-level block here.
func loopbackPrefix() netip.Prefix { return netip.MustParsePrefix("127.0.0.0/8") }
