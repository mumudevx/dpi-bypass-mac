package resolve

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// encryptedStreamFiles are the only files allowed to name a stream network.
//
// MEASUREMENTS.md §2 measures plaintext DNS over TCP as connection-reset at
// every port tested — `dig +tcp @8.8.8.8 discord.com` and `dig +tcp -p 1253
// @77.88.8.8 discord.com` both reset — so a truncation fallback to TCP/53 fails
// for exactly the names this tool exists to reach. DoT/853 and DoH/443 are
// different transports, measured working (DOSSIER GT4), and they are the only
// reason a stream is opened here at all.
var encryptedStreamFiles = map[string]bool{
	"doh.go": true,
	"dot.go": true,
}

// TestNoPlaintextTCPPathExists walks this package's own source and asserts that
// no file outside the encrypted transports can name a stream network. This is
// the difference between "TCP DNS is disabled" and "TCP DNS is unreachable":
// a config key cannot re-enable a code path that does not exist.
func TestNoPlaintextTCPPathExists(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var findings []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if encryptedStreamFiles[name] {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			switch s {
			case "tcp", "tcp4", "tcp6":
				p := fset.Position(lit.Pos())
				findings = append(findings,
					name+":"+strconv.Itoa(p.Line)+": names the stream network "+strconv.Quote(s))
			}
			return true
		})
	}
	if len(findings) > 0 {
		t.Fatalf("plaintext DNS must have no TCP path at all (MEASUREMENTS.md §2):\n  %s",
			strings.Join(findings, "\n  "))
	}
}

// TestTruncationNeverDialsTCP is the same claim tested on the wire: a truncated
// plaintext answer is the RFC's cue to retry over TCP, and this chain must
// re-ask an encrypted resolver or return the truncated message instead. A TCP
// listener stands where a fallback would land and fails the test if reached.
func TestTruncationNeverDialsTCP(t *testing.T) {
	trap := tcpTrap(t)

	// A plaintext rung at the trap's own address. Its UDP exchange fails
	// because nothing is listening on UDP there; a TCP fallback would connect.
	deadUDP, err := NewUDP("udp-at-trap", trap, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := fastChain(t, Options{Resolvers: []Resolver{
		truncating(t, "udp-alt", "udp-alt"),
		deadUDP,
	}})

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !Truncated(ans) {
		t.Fatal("with no encrypted rung, the truncated answer is what the caller gets")
	}
	// Give any stray dial a moment to land on the trap before it is closed.
	time.Sleep(50 * time.Millisecond)
}

// TestBlockedNameSurvivesTheWholeCensor drives the measured DNS censorship end
// to end: port 53 drops the query, the ISP resolver answers the sinkhole, TCP
// is a trap, and the alternate port carries the real answer.
func TestBlockedNameSurvivesTheWholeCensor(t *testing.T) {
	tcpTrap(t)
	p53, err := NewUDP("udp-53", censorPort53(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	isp, err := NewUDP("isp", censorSystemResolver(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	alt, err := NewUDP("udp-alt", censorAltPort(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The ISP resolver sits ahead of the alternate port on purpose: a chain
	// that accepts its sinkhole answer never reaches the rung that works.
	c := fastChain(t, Options{Resolvers: []Resolver{p53, isp, alt}, PerTry: 250 * time.Millisecond})

	ans, err := c.Exchange(context.Background(), mustQuery(t, "discord.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	addrs := AnswerAddrs(ans)
	for _, a := range addrs {
		if a == ttSinkhole {
			t.Fatalf("the BTK sinkhole reached the caller: %v", addrs)
		}
	}
	if got := addrStrings(addrs); got != addrStrings(genuineAnswer) {
		t.Fatalf("answer = %s, want the measured %s", got, addrStrings(genuineAnswer))
	}

	h := c.Health()
	if h[0].OK {
		t.Fatalf("port 53 drops this name: %+v", h[0])
	}
	if !h[1].Signal.Sinkhole {
		t.Fatalf("the ISP resolver's answer must be recorded as a sinkhole: %+v", h[1])
	}
	if !h[2].OK {
		t.Fatalf("the alternate port must be healthy: %+v", h[2])
	}

	// Resolve reaches the same answer through the same chain.
	got, err := c.Resolve(context.Background(), "discord.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, a := range got {
		if a == ttSinkhole {
			t.Fatalf("the BTK sinkhole reached the caller: %v", got)
		}
	}
	time.Sleep(50 * time.Millisecond)
}
