package resolve

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/mumudevx/dpb/internal/flow"
)

// AltPort is a plaintext UDP resolver reachable on a port other than 53.
//
// MEASUREMENTS.md §2 measured these directly: `dig -p 1253 @77.88.8.8
// discord.com` returned 162.159.128.233 and 162.159.136.232, and `dig -p 9953
// @9.9.9.9 discord.com` returned 162.159.135.232 and 162.159.128.233, while the
// same queries on port 53 to the same servers timed out. Alternate-port UDP is
// therefore a first-class rung of the chain, not a curiosity: it is the only
// plaintext transport that works here, and it works without TLS, without HTTP
// and without a certificate store.
type AltPort struct {
	Label string
	Addr  string
}

// DefaultAltPorts is the measured set, in the order §2 lists them.
func DefaultAltPorts() []AltPort {
	return []AltPort{
		{Label: "udp-yandex-1253", Addr: "77.88.8.8:1253"},
		{Label: "udp-quad9-9953", Addr: "9.9.9.9:9953"},
	}
}

// NewAltPortResolvers builds DefaultAltPorts.
func NewAltPortResolvers(d *net.Dialer) ([]Resolver, error) {
	aps := DefaultAltPorts()
	out := make([]Resolver, 0, len(aps))
	for _, ap := range aps {
		r, err := NewUDP(ap.Label, ap.Addr, d)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// rankTimeout bounds one liveness probe. A resolver that cannot answer a
// control name inside this is ranked last, not removed: a slow resolver is
// still infinitely better than the sinkhole.
const rankTimeout = 2 * time.Second

// Rank orders resolvers by measured liveness against a control name.
//
// The control must be a name that is NOT blocked here — MEASUREMENTS.md §2 uses
// google.com against every transport for exactly this purpose — because a
// blocked name would rank a working resolver as dead. Ranking is stable: equal
// results keep their configured order, so the shipped chain order survives a
// tie and the result is reproducible.
func Rank(ctx context.Context, rs []Resolver, control string, logf func(string, ...any)) []Resolver {
	if len(rs) < 2 {
		return append([]Resolver(nil), rs...)
	}
	query, err := NewQuery(control, dns.TypeA)
	if err != nil {
		if logf != nil {
			logf("resolve: rank: bad control name %q: %v; keeping configured order", control, err)
		}
		return append([]Resolver(nil), rs...)
	}

	type score struct {
		idx     int
		live    bool
		latency time.Duration
	}
	scores := make([]score, len(rs))
	var wg sync.WaitGroup
	for i, r := range rs {
		scores[i] = score{idx: i, latency: rankTimeout}
		wg.Add(1)
		flow.Safe("resolve.rank."+r.Label(), logf, func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, rankTimeout)
			defer cancel()
			start := time.Now()
			ans, err := r.Exchange(c, query)
			d := time.Since(start)
			if err != nil {
				if logf != nil {
					logf("resolve: rank: %s failed the %s control: %v", r.Label(), control, err)
				}
				return
			}
			if Rcode(ans) != dns.RcodeSuccess || len(AnswerAddrs(ans)) == 0 {
				if logf != nil {
					logf("resolve: rank: %s answered the %s control with rcode %d and %d addresses",
						r.Label(), control, Rcode(ans), len(AnswerAddrs(ans)))
				}
				return
			}
			scores[i] = score{idx: i, live: true, latency: d}
		})
	}
	wg.Wait()

	sort.SliceStable(scores, func(a, b int) bool {
		if scores[a].live != scores[b].live {
			return scores[a].live
		}
		if !scores[a].live {
			return false // dead resolvers keep their configured order
		}
		return scores[a].latency < scores[b].latency
	})
	out := make([]Resolver, 0, len(rs))
	for _, s := range scores {
		out = append(out, rs[s.idx])
	}
	return out
}

// ErrNoCleanTransport is what a preflight reports when every transport in the
// chain is either dropped or poisoned. No packet strategy fixes a poisoned
// resolver, so the honest answer is to stop rather than to proceed with
// answers we know are wrong.
var ErrNoCleanTransport = fmt.Errorf("resolve: no DNS transport on this network returns a clean answer")
