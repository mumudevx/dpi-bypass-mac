package proxyfe_test

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/proxyfe"
)

func patternsOf(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, r := range config.Mandatory() {
		out = append(out, r.Pattern)
	}
	return out
}

// The two refusals the PAC is built around.
func TestPACNeverResolvesAndNeverFallsBackToDirect(t *testing.T) {
	t.Parallel()
	p := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080, Bypass: patternsOf(t)}
	s := string(p.Active())

	// dnsResolve would hand every hostname the browser visits to the system
	// resolver, which answers blocked names with the ISP sinkhole.
	for _, forbidden := range []string{"dnsResolve", "myIpAddress", "dnsDomainLevels"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("the PAC calls %s, which leaks the name to the system resolver", forbidden)
		}
	}
	// "PROXY host:port; DIRECT" would send an unmodified ClientHello for a
	// blocked name the moment dpb hiccuped.
	if strings.Contains(s, "; DIRECT") {
		t.Error("the PAC has a DIRECT fallback, which silently leaks on any dpb error")
	}
	if !strings.Contains(s, `return "PROXY 127.0.0.1:8080"`) {
		t.Errorf("the PAC never returns the proxy:\n%s", s)
	}
}

func TestPACSendsBypassedNamesDirect(t *testing.T) {
	t.Parallel()
	p := &proxyfe.PAC{
		Host:   "127.0.0.1",
		Port:   8080,
		Bypass: []string{"isbank.com.tr", ".gov.tr", "*.cdn.example", "=exact.example", "203.0.113.0/24"},
	}
	s := string(p.Active())

	for _, want := range []string{
		`"isbank.com.tr"`, `"gov.tr"`, `"cdn.example"`, `"exact.example"`,
		`isInNet(host, "203.0.113.0", "255.255.255.0")`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the PAC does not carry %s:\n%s", want, s)
		}
	}
	// A leading dot is policy's spelling convenience for the same anchored
	// rule, not a separate pattern; emitting ".gov.tr" as the base would make
	// every comparison in the script fail.
	if strings.Contains(s, `".gov.tr"`) {
		t.Error("the leading dot was not stripped, so the rule can never match")
	}
}

func TestPACIsDeterministic(t *testing.T) {
	t.Parallel()
	a := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080, Bypass: []string{"b.test", "a.test", "b.test"}}
	b := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080, Bypass: []string{"b.test", "a.test"}}
	if a.SHA256() != b.SHA256() {
		t.Fatal("the PAC is not a deterministic function of its inputs, so its digest cannot be verified")
	}
	if strings.Count(string(a.Active()), `"b.test"`) != 1 {
		t.Fatal("a duplicated pattern was emitted twice")
	}
}

func TestPACSuspendedIsAllDirect(t *testing.T) {
	t.Parallel()
	var off atomic.Bool
	p := &proxyfe.PAC{
		Host: "127.0.0.1", Port: 8080,
		Bypass:    []string{"a.test"},
		Suspended: off.Load,
	}
	if strings.Contains(string(p.Script()), "DIRECT\"; }") {
		t.Fatal("the running script is already the suspended one")
	}
	off.Store(true)
	s := string(p.Script())
	if !strings.Contains(s, `return "DIRECT"`) || strings.Contains(s, "PROXY") {
		t.Fatalf("the suspended script is not all-DIRECT:\n%s", s)
	}
	// The ACTIVE script is what goes on disk, so the disk copy does not flip
	// under a captive portal.
	if strings.Contains(string(p.Active()), "suspended") {
		t.Fatal("Active returned the suspended script")
	}
}

func TestPACURL(t *testing.T) {
	t.Parallel()
	p := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080}
	if got := p.URL(); got != "http://127.0.0.1:8080/dpb.pac" {
		t.Fatalf("URL = %q", got)
	}
}

func TestPACIPv6CIDRIsDeclaredUnenforced(t *testing.T) {
	t.Parallel()
	p := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080, Bypass: []string{"2001:db8::/32"}}
	s := string(p.Active())
	// PAC has no portable IPv6 network predicate. Saying so in the file beats
	// silently dropping the entry, which would look like it was enforced.
	if !strings.Contains(s, "NOT ENFORCED HERE: 2001:db8::/32") {
		t.Fatalf("an unenforceable entry was dropped silently:\n%s", s)
	}
}

func TestServerServesThePAC(t *testing.T) {
	t.Parallel()
	pac := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080, Bypass: []string{"isbank.com.tr"}}
	h := serveTest(t, wiring{dialer: newMapDialer(), pac: pac})

	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "GET /dpb.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-ns-proxy-autoconfig" {
		t.Fatalf("content type = %q; macOS ignores a PAC served as anything else", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(pac.Active()) {
		t.Fatal("the served script is not the one written to disk")
	}
	if st := h.srv.Stats(); st.PAC != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestServerAnswers404ForAnythingElse(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer(), pac: &proxyfe.PAC{Host: "127.0.0.1", Port: 8080}})
	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "GET /wat HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPACPathIsRefusedWithoutAPAC(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "GET /dpb.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404 when no PAC is configured", resp.StatusCode)
	}
}
