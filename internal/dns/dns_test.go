package dns

import (
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

func TestDoHResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("93.184.216.34"),
		})
		packed, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	defer srv.Close()

	r, err := NewDoH(srv.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	ips, err := r.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("ips = %v", ips)
	}
}

type fakeResolver struct {
	name  string
	ips   []net.IP
	err   error
	calls int
}

func (f *fakeResolver) Label() string { return f.name }
func (f *fakeResolver) Resolve(_ context.Context, _ string) ([]net.IP, error) {
	f.calls++
	return f.ips, f.err
}

func TestChainFallback(t *testing.T) {
	bad := &fakeResolver{name: "bad", err: errors.New("boom")}
	good := &fakeResolver{name: "good", ips: []net.IP{net.ParseIP("10.0.0.1")}}
	c := NewChain([]Resolver{bad, good}, time.Minute, nil)

	ips, err := c.Resolve(context.Background(), "blocked.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "10.0.0.1" {
		t.Fatalf("ips = %v", ips)
	}
	if bad.calls != 1 || good.calls != 1 {
		t.Fatalf("calls bad=%d good=%d", bad.calls, good.calls)
	}

	// Second lookup must be served from cache (no new resolver calls).
	if _, err := c.Resolve(context.Background(), "blocked.example"); err != nil {
		t.Fatal(err)
	}
	if good.calls != 1 {
		t.Fatalf("cache miss: good.calls = %d", good.calls)
	}
}

func TestChainAllFail(t *testing.T) {
	c := NewChain([]Resolver{&fakeResolver{name: "x", err: errors.New("nope")}}, time.Minute, nil)
	if _, err := c.Resolve(context.Background(), "host.example"); err == nil {
		t.Fatal("expected error when all resolvers fail")
	}
}

func TestIPLiteralPassthrough(t *testing.T) {
	c := NewChain(nil, time.Minute, nil)
	ips, err := c.Resolve(context.Background(), "203.0.113.5")
	if err != nil || len(ips) != 1 || ips[0].String() != "203.0.113.5" {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}
