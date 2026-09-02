package resolve

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestNewUDPRefusesAHostname is MEASUREMENTS.md §5.4 made structural. The
// compatibility matrix's first run scored every emitter 0/6 because a hostname
// dial fell through to the system resolver, which answers the BTK sinkhole for
// every blocked name. A resolver constructor that accepts a hostname is that
// bug waiting to happen, so it does not exist.
func TestNewUDPRefusesAHostname(t *testing.T) {
	for _, addr := range []string{"dns.google:53", "dns.google", "77.88.8.8", "[::1]", "localhost:53"} {
		if _, err := NewUDP("x", addr, nil); err == nil {
			t.Fatalf("NewUDP(%q) must be refused", addr)
		} else if !strings.Contains(err.Error(), "5.4") {
			t.Fatalf("NewUDP(%q) error must cite the measurement, got %v", addr, err)
		}
	}
	if _, err := NewUDP("x", "77.88.8.8:0", nil); err == nil {
		t.Fatal("port 0 must be refused")
	}
}

// TestUDPTransportLabels: port 53 is measured as per-QNAME dropped here and the
// alternate ports are measured working (§2), so the two must be distinguishable
// by the chain and in `dpb dns check`.
func TestUDPTransportLabels(t *testing.T) {
	r53, err := NewUDP("", "8.8.8.8:53", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r53.Transport() != "udp" {
		t.Fatalf("port 53 transport = %q", r53.Transport())
	}
	if r53.Label() != "udp-8.8.8.8:53" {
		t.Fatalf("default label = %q", r53.Label())
	}
	alt, err := NewUDP("yandex", "77.88.8.8:1253", nil)
	if err != nil {
		t.Fatal(err)
	}
	if alt.Transport() != "udp-alt" {
		t.Fatalf("alt-port transport = %q", alt.Transport())
	}
	if alt.Label() != "yandex" {
		t.Fatalf("label = %q", alt.Label())
	}
}

// TestForbidTCP is the guard a config layer calls so `allow_tcp53 = true` fails
// with the measurement attached instead of producing a resolver that cannot
// work on this ISP.
func TestForbidTCP(t *testing.T) {
	for _, n := range []string{"udp", "udp4", "udp6"} {
		if err := ForbidTCP(n); err != nil {
			t.Fatalf("ForbidTCP(%q) = %v", n, err)
		}
	}
	for _, n := range []string{"tcp", "tcp4", "tcp6", "", "unix"} {
		err := ForbidTCP(n)
		if !errors.Is(err, ErrTCPForbidden) {
			t.Fatalf("ForbidTCP(%q) = %v, want ErrTCPForbidden", n, err)
		}
	}
}

func TestUDPExchangeAgainstTheAltPort(t *testing.T) {
	addr := censorAltPort(t)
	r, err := NewUDP("alt", addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0x0f0f); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ans, err := r.Exchange(ctx, q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := MsgID(ans)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0x0f0f {
		t.Fatalf("the caller's transaction ID must be restored, got %#x", id)
	}
	if got := addrStrings(AnswerAddrs(ans)); got != addrStrings(genuineAnswer) {
		t.Fatalf("answer = %s, want the measured %s", got, addrStrings(genuineAnswer))
	}
}

// TestUDPPort53DropsTheBlockedName reproduces §2's central DNS fact: the query
// is not refused, it disappears, so the only way past it is a deadline.
func TestUDPPort53DropsTheBlockedName(t *testing.T) {
	addr := censorPort53(t)
	r, err := NewUDP("p53", addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := r.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err == nil {
		t.Fatal("a dropped query must fail, not hang forever")
	}
	// The same socket answers a benign name, so this is per-QNAME and not an
	// unreachable server.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if _, err := r.Exchange(ctx2, mustQuery(t, "google.com", dns.TypeA)); err != nil {
		t.Fatalf("the benign control must still answer: %v", err)
	}
}

// TestUDPIgnoresSpoofedAnswers: plaintext UDP is a first-class rung here, and a
// randomised ID plus a question check is the only anti-spoofing it has.
func TestUDPIgnoresSpoofedAnswers(t *testing.T) {
	real := answerAddr(t)
	// This endpoint writes twice: a forged answer with a wrong transaction ID
	// first, then the real one.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		bad := buildAnswer(t, q, 60, netip.MustParseAddr("6.6.6.6"))
		if bad != nil {
			binary.BigEndian.PutUint16(bad[0:2], binary.BigEndian.Uint16(q[0:2])^0xffff)
			_, _ = pc.WriteTo(bad, from)
		}
		if good := buildAnswer(t, q, 60, real); good != nil {
			_, _ = pc.WriteTo(good, from)
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-done })

	r, err := NewUDP("spoof", pc.LocalAddr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ans, err := r.Exchange(ctx, mustQuery(t, "google.com", dns.TypeA))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	got := AnswerAddrs(ans)
	if len(got) != 1 || got[0] != real {
		t.Fatalf("the spoofed answer was accepted: %v", got)
	}
}

func answerAddr(t *testing.T) netip.Addr {
	t.Helper()
	return netip.MustParseAddr("142.250.187.174")
}

func TestUDPExchangeRejectsShortQuery(t *testing.T) {
	r, err := NewUDP("x", "127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Exchange(context.Background(), []byte{1, 2}); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("short query = %v", err)
	}
}

func TestUDPExchangeReportsDialFailure(t *testing.T) {
	// A dialer bound to an address it cannot use makes the dial itself fail,
	// which must surface as an error the chain can advance past.
	d := &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 0}}
	r, err := NewUDP("x", "127.0.0.1:53", d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := r.Exchange(ctx, mustQuery(t, "google.com", dns.TypeA)); err == nil {
		t.Fatal("an unusable local address must fail the exchange")
	}
}

func TestQuestionLabelOnGarbage(t *testing.T) {
	if got := questionLabel([]byte{1, 2, 3}); got != "<unparseable question>" {
		t.Fatalf("questionLabel = %q", got)
	}
}
