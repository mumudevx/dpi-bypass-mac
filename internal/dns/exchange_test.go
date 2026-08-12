package dns

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// packQuery builds a packed A-record query carrying the given message ID.
func packQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Id = id
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return packed
}

// packReply builds a packed reply to q with the given rcode.
func packReply(t *testing.T, q []byte, rcode int) []byte {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(q); err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	r := new(dns.Msg)
	r.SetReply(m)
	r.Rcode = rcode
	packed, err := r.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}
	return packed
}

// fakeExchanger is a Resolver that also answers raw wire queries.
type fakeExchanger struct {
	name     string
	reply    []byte
	err      error
	calls    int
	gotQuery []byte
}

func (f *fakeExchanger) Label() string { return f.name }

func (f *fakeExchanger) Resolve(context.Context, string) ([]net.IP, error) {
	return nil, errors.New("not used")
}

func (f *fakeExchanger) Exchange(_ context.Context, q []byte) ([]byte, error) {
	f.calls++
	f.gotQuery = append([]byte(nil), q...)
	return f.reply, f.err
}

func TestChainExchangeReturnsFirstReply(t *testing.T) {
	q := packQuery(t, 0x1234, "example.com")
	first := &fakeExchanger{name: "first", reply: packReply(t, q, dns.RcodeSuccess)}
	second := &fakeExchanger{name: "second", reply: packReply(t, q, dns.RcodeSuccess)}
	c := NewChain([]Resolver{first, second}, time.Minute, nil)

	reply, err := c.Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !bytes.Equal(reply, first.reply) {
		t.Fatalf("reply = %x, want %x", reply, first.reply)
	}
	if second.calls != 0 {
		t.Fatalf("second resolver called %d times, want 0", second.calls)
	}
}

func TestChainExchangeFallsBackWhenResolverErrors(t *testing.T) {
	q := packQuery(t, 0x1234, "blocked.example")
	bad := &fakeExchanger{name: "bad", err: errors.New("boom")}
	good := &fakeExchanger{name: "good", reply: packReply(t, q, dns.RcodeSuccess)}
	c := NewChain([]Resolver{bad, good}, time.Minute, nil)

	reply, err := c.Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !bytes.Equal(reply, good.reply) {
		t.Fatalf("reply came from the wrong resolver")
	}
	if bad.calls != 1 || good.calls != 1 {
		t.Fatalf("calls bad=%d good=%d", bad.calls, good.calls)
	}
}

func TestChainExchangeFallsBackOnServfail(t *testing.T) {
	q := packQuery(t, 0x1234, "blocked.example")
	failing := &fakeExchanger{name: "servfail", reply: packReply(t, q, dns.RcodeServerFailure)}
	good := &fakeExchanger{name: "good", reply: packReply(t, q, dns.RcodeSuccess)}
	c := NewChain([]Resolver{failing, good}, time.Minute, nil)

	reply, err := c.Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !bytes.Equal(reply, good.reply) {
		t.Fatalf("SERVFAIL was returned instead of falling back")
	}
}

func TestChainExchangeKeepsNXDOMAIN(t *testing.T) {
	q := packQuery(t, 0x1234, "nope.example")
	nx := &fakeExchanger{name: "nx", reply: packReply(t, q, dns.RcodeNameError)}
	next := &fakeExchanger{name: "next", reply: packReply(t, q, dns.RcodeSuccess)}
	c := NewChain([]Resolver{nx, next}, time.Minute, nil)

	reply, err := c.Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !bytes.Equal(reply, nx.reply) {
		t.Fatalf("NXDOMAIN is an answer, not a failure — must not fall back")
	}
	if next.calls != 0 {
		t.Fatalf("next resolver called %d times, want 0", next.calls)
	}
}

func TestChainExchangeSkipsResolversWithoutWireSupport(t *testing.T) {
	q := packQuery(t, 0x1234, "example.com")
	plain := &fakeResolver{name: "plain"}
	wire := &fakeExchanger{name: "wire", reply: packReply(t, q, dns.RcodeSuccess)}
	c := NewChain([]Resolver{plain, wire}, time.Minute, nil)

	if _, err := c.Exchange(context.Background(), q); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if plain.calls != 0 {
		t.Fatalf("plain resolver was consulted for a wire query")
	}
}

func TestChainExchangeAllFail(t *testing.T) {
	q := packQuery(t, 0x1234, "example.com")
	c := NewChain([]Resolver{&fakeExchanger{name: "x", err: errors.New("nope")}}, time.Minute, nil)
	if _, err := c.Exchange(context.Background(), q); err == nil {
		t.Fatal("expected an error when every resolver fails")
	}
}

func TestChainExchangeRejectsShortQuery(t *testing.T) {
	c := NewChain([]Resolver{&fakeExchanger{name: "x"}}, time.Minute, nil)
	if _, err := c.Exchange(context.Background(), []byte{0x12, 0x34}); err == nil {
		t.Fatal("expected an error for a truncated query")
	}
}

// RFC 8484 §4.1 recommends a zero message ID so DoH replies are HTTP-cacheable.
// The client's original ID must still come back, or the stub resolver drops the
// answer as unsolicited.
func TestDoHExchangeZeroesIDOnTheWireAndRestoresIt(t *testing.T) {
	var sawID uint16 = 0xFFFF
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) < 2 {
			http.Error(w, "short", http.StatusBadRequest)
			return
		}
		sawID = uint16(body[0])<<8 | uint16(body[1])
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(q)
		packed, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	defer srv.Close()

	r, err := NewDoH(srv.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	ex, ok := r.(Exchanger)
	if !ok {
		t.Fatal("DoH resolver does not implement Exchanger")
	}

	q := packQuery(t, 0xBEEF, "example.com")
	reply, err := ex.Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if sawID != 0 {
		t.Fatalf("upstream saw message ID %#x, want 0", sawID)
	}
	gotID := uint16(reply[0])<<8 | uint16(reply[1])
	if gotID != 0xBEEF {
		t.Fatalf("reply ID = %#x, want 0xBEEF", gotID)
	}
	if q[0] != 0xBE || q[1] != 0xEF {
		t.Fatal("Exchange mutated the caller's query buffer")
	}
}

func TestUDPResolverExchange(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1500)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		m := new(dns.Msg)
		if err := m.Unpack(buf[:n]); err != nil {
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(m)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.9"),
		})
		packed, _ := reply.Pack()
		_, _ = pc.WriteTo(packed, addr)
	}()

	r, err := NewUDP(pc.LocalAddr().String(), "local")
	if err != nil {
		t.Fatal(err)
	}
	ex, ok := r.(Exchanger)
	if !ok {
		t.Fatal("UDP resolver does not implement Exchanger")
	}

	reply, err := ex.Exchange(context.Background(), packQuery(t, 0x0042, "example.com"))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(reply); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if m.Id != 0x0042 {
		t.Fatalf("reply ID = %#x, want 0x0042", m.Id)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answer))
	}
}
