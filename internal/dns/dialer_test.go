package dns

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/miekg/dns"
)

// startEchoDNS runs a local UDP resolver that answers every A query with a
// fixed address, and returns its host:port.
func startEchoDNS(t *testing.T, answer string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			m := new(dns.Msg)
			if err := m.Unpack(buf[:n]); err != nil {
				continue
			}
			reply := new(dns.Msg)
			reply.SetReply(m)
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(answer),
			})
			packed, _ := reply.Pack()
			_, _ = pc.WriteTo(packed, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// In TUN mode dpb's own fallback query would otherwise leave on the default
// route, get pulled straight back into the utun by the split-default routes,
// hit serveDNS on port 53 and re-enter the chain — recursing until timeouts
// fire. Binding the resolver's socket to the uplink is what breaks the cycle,
// so the supplied dialer must actually be the one that dials.
func TestUDPResolverDialsThroughTheSuppliedDialer(t *testing.T) {
	addr := startEchoDNS(t, "203.0.113.7")

	var used atomic.Bool
	dialer := &net.Dialer{
		Control: func(string, string, syscall.RawConn) error {
			used.Store(true)
			return nil
		},
	}

	r, err := ResolverFromSpec("udp", addr, "local", dialer)
	if err != nil {
		t.Fatalf("ResolverFromSpec: %v", err)
	}
	ips, err := r.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.7" {
		t.Fatalf("ips = %v", ips)
	}
	if !used.Load() {
		t.Fatal("resolver ignored the supplied dialer — its query would re-enter the tun")
	}
}

func TestUDPResolverExchangeDialsThroughTheSuppliedDialer(t *testing.T) {
	addr := startEchoDNS(t, "203.0.113.8")

	var used atomic.Bool
	dialer := &net.Dialer{
		Control: func(string, string, syscall.RawConn) error {
			used.Store(true)
			return nil
		},
	}

	r, err := ResolverFromSpec("udp", addr, "local", dialer)
	if err != nil {
		t.Fatalf("ResolverFromSpec: %v", err)
	}
	ex, ok := r.(Exchanger)
	if !ok {
		t.Fatal("UDP resolver does not implement Exchanger")
	}
	if _, err := ex.Exchange(context.Background(), packQuery(t, 0x21, "example.com")); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !used.Load() {
		t.Fatal("wire exchange ignored the supplied dialer")
	}
}

func TestResolverFromSpecAcceptsNilDialer(t *testing.T) {
	addr := startEchoDNS(t, "203.0.113.9")
	r, err := ResolverFromSpec("udp", addr, "local", nil)
	if err != nil {
		t.Fatalf("ResolverFromSpec: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "example.com"); err != nil {
		t.Fatalf("Resolve with default dialer: %v", err)
	}
}
