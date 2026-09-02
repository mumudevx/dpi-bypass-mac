package probe_test

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

// The fake resolvers below are the three shapes MEASUREMENTS.md §2 measured on
// this line, as resolve.Resolver implementations:
//
//	clean     — answers with a genuine address (alternate-port UDP, DoH, DoT)
//	dropping  — silence on a blocked QNAME, an answer on anything else (:53)
//	sinkhole  — 195.175.254.2 for a blocked QNAME (the ISP resolver)
//
// A control name is answered by all three, which is exactly why a preflight
// that only asks the control cannot tell them apart.

const (
	controlName  = "google.com."
	sinkholeAddr = "195.175.254.2"
	genuineAddr  = "162.159.128.233"
)

type cleanResolver struct {
	label string
	delay time.Duration
}

func (r cleanResolver) Label() string     { return r.label }
func (r cleanResolver) Transport() string { return "udp-alt" }
func (r cleanResolver) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	if r.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(r.delay):
		}
	}
	return answer(q, genuineAddr)
}

type sinkholeResolver struct{ label string }

func (r sinkholeResolver) Label() string     { return r.label }
func (r sinkholeResolver) Transport() string { return "udp" }
func (r sinkholeResolver) Exchange(_ context.Context, q []byte) ([]byte, error) {
	if isControl(q) {
		return answer(q, genuineAddr)
	}
	return answer(q, sinkholeAddr)
}

type droppingResolver struct{ label string }

func (r droppingResolver) Label() string     { return r.label }
func (r droppingResolver) Transport() string { return "udp" }
func (r droppingResolver) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	if isControl(q) {
		return answer(q, genuineAddr)
	}
	// A per-QNAME drop is silence, not an error, so the caller's deadline is
	// what ends it. Waiting for the context is the honest shape.
	<-ctx.Done()
	return nil, ctx.Err()
}

func isControl(q []byte) bool {
	var m dns.Msg
	if err := m.Unpack(q); err != nil || len(m.Question) == 0 {
		return false
	}
	return m.Question[0].Name == controlName
}

func answer(q []byte, ip string) ([]byte, error) {
	var m dns.Msg
	if err := m.Unpack(q); err != nil {
		return nil, err
	}
	if len(m.Question) == 0 {
		return nil, errors.New("no question")
	}
	resp := new(dns.Msg)
	resp.SetReply(&m)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name: m.Question[0].Name, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 60,
		},
		A: net.ParseIP(ip),
	})
	return resp.Pack()
}

// loopbackResolver answers everything with 127.0.0.1, so a test can exercise
// the unpinned path — where the prober resolves a target through its OWN chain
// and pins it — without any dial leaving the machine.
type loopbackResolver struct{ label string }

func (r loopbackResolver) Label() string     { return r.label }
func (r loopbackResolver) Transport() string { return "udp-alt" }
func (r loopbackResolver) Exchange(_ context.Context, q []byte) ([]byte, error) {
	return answer(q, "127.0.0.1")
}
