package tunfe

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/resolve"
)

// The IPv6 gate, end to end through the tunnel: an application asks the
// captured resolver for AAAA and gets back exactly what this run can honour.
//
// This is the M17 clause that matters most. A tunnel capturing only IPv4 while
// its own resolver hands applications real AAAA records is a silent fail-open —
// the traffic leaves on a path dpb never sees, on a line where DOSSIER GT19
// records the IPv6 sinkhole as registered to BTK itself. The gate is what makes
// "we did not capture IPv6" and "we do not answer AAAA" the same fact.

// aaaaResolver answers both families from a table, so the suppression under
// test is the policy's and not the fixture's.
type aaaaResolver struct {
	v4, v6 netip.Addr
}

func (r *aaaaResolver) Label() string     { return "scripted6" }
func (r *aaaaResolver) Transport() string { return "doh" }

func (r *aaaaResolver) Exchange(_ context.Context, query []byte) ([]byte, error) {
	var m dns.Msg
	if err := m.Unpack(query); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.SetReply(&m)
	if len(m.Question) == 1 {
		q := m.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   r.v4.AsSlice(),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: r.v6.AsSlice(),
			})
		}
	}
	return resp.Pack()
}

func aaaaQuery(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeAAAA)
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return b
}

// serveAAAAThroughTunnel asks the tunnel's own resolver for an AAAA record with
// the given IPv6 capture state and returns the reply.
func serveAAAAThroughTunnel(t *testing.T, gate *IPv6Gate) *dns.Msg {
	t.Helper()
	chain := resolve.NewChain(resolve.Options{
		Resolvers:   []resolve.Resolver{&aaaaResolver{v4: originIP, v6: originV6}},
		Detector:    resolve.NewDetector(nil, nil),
		AAAA:        resolve.AAAAAuto,
		V4Path:      func() bool { return true },
		V6Protected: gate.Captured,
		Logf:        t.Logf,
	})
	l := newLab(t, labOpts{
		dns:     resolve.NewServer(chain, t.Logf),
		udp:     &countingUDPDialer{},
		reverse: policy.NewReverseMap(16),
	})

	client, err := l.dialUDP(netip.AddrPortFrom(resolverIP, 53))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(aaaaQuery(t, "discord.com.")); err != nil {
		t.Fatalf("write query: %v", err)
	}
	var m dns.Msg
	if err := m.Unpack(readDNSDatagram(t, client)); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	return &m
}

// TestTunnelSuppressesAAAAWhenIPv6IsNotCaptured: NOERROR with an SOA, never
// NXDOMAIN — an NXDOMAIN would be a lie about the name rather than a statement
// about this address family, and stubs cache it for the whole zone.
func TestTunnelSuppressesAAAAWhenIPv6IsNotCaptured(t *testing.T) {
	m := serveAAAAThroughTunnel(t, &IPv6Gate{})
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Fatalf("an AAAA record was handed to an application for traffic this run cannot protect: %v", m.Answer)
	}
	if len(m.Ns) != 1 {
		t.Fatalf("want one SOA in the authority section so the stub gets a negative TTL, got %v", m.Ns)
	}
	if _, ok := m.Ns[0].(*dns.SOA); !ok {
		t.Fatalf("authority record is %T, want an SOA", m.Ns[0])
	}
}

// TestTunnelServesAAAAOnceIPv6IsCaptured is the other half: with ::/1 and
// 8000::/1 installed and verified, the flow comes to us and the record is safe
// to hand out. Suppressing it then would amputate half the internet for no
// reason.
func TestTunnelServesAAAAOnceIPv6IsCaptured(t *testing.T) {
	gate := &IPv6Gate{}
	gate.Set(true)
	m := serveAAAAThroughTunnel(t, gate)
	if len(m.Answer) != 1 {
		t.Fatalf("AAAA was suppressed on a tunnel carrying IPv6: %v", m)
	}
	aaaa, ok := m.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer is %T, want AAAA", m.Answer[0])
	}
	got, _ := netip.AddrFromSlice(aaaa.AAAA)
	if got != originV6 {
		t.Fatalf("AAAA = %v, want %v", got, originV6)
	}
}
