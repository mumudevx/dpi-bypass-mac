package netstate

import (
	"context"
	"fmt"
	"strings"
)

func init() { reviveByKind[OpDNSServers] = reviveDNS }

type dnsRevert struct {
	Servers  []string            `json:"servers"`
	Services []string            `json:"services"`
	Prev     map[string][]string `json:"prev"`
}

// dnsOp points a service's resolvers at a list of servers with networksetup(8)
// and verifies the result with `scutil --dns`, which reports the resolver
// configuration mDNSResponder is actually using.
//
// Callers are expected to pass the loopback resolver followed by the machine's
// original servers, so a dead dpb degrades to plaintext DNS in one RTT rather
// than to no DNS at all. That fail-open choice lives in the caller; this Op
// just applies the list it is given.
type dnsOp struct {
	run      Runner
	servers  []string
	services []string
	prev     map[string][]string
	prepared bool
}

// NewDNSServers returns an Op setting the given resolvers on the given
// services. An empty services list means "every enabled network service".
func NewDNSServers(r Runner, servers []string, services []string) Op {
	return &dnsOp{
		run:      r,
		servers:  append([]string(nil), servers...),
		services: append([]string(nil), services...),
	}
}

// canAdopt is always false: a resolver list that already equals ours is our own
// residue, not the user's configuration. See proxyOp.canAdopt.
func (o *dnsOp) canAdopt() bool { return false }

func (o *dnsOp) Kind() OpKind { return OpDNSServers }

func (o *dnsOp) ID() string {
	return "dns.servers:" + strings.Join(o.services, ",")
}

func (o *dnsOp) Describe() string {
	svcs := strings.Join(o.services, ", ")
	if svcs == "" {
		svcs = "every enabled service"
	}
	return fmt.Sprintf("set DNS servers %s on %s", strings.Join(o.servers, " "), svcs)
}

func (o *dnsOp) runner(e Env) Runner {
	if o.run != nil {
		return o.run
	}
	return e.runner()
}

// sys is the Port this Op mutates through, built from the Op's own Runner when
// it has one. See routeOp.sys.
func (o *dnsOp) sys(e Env) Port {
	env := e
	env.Runner = o.runner(e)
	return env.sys()
}

func (o *dnsOp) prepare(ctx context.Context, e Env) error {
	if o.prepared {
		return nil
	}
	if len(o.servers) == 0 {
		return fmt.Errorf("netstate: no DNS servers given")
	}
	sys := o.sys(e)
	if len(o.services) == 0 {
		// Proxy().Services is the Port's one enumeration of network services;
		// it is not proxy-specific, and resolvers are set on the same list.
		svcs, err := sys.Proxy().Services(ctx)
		if err != nil {
			return err
		}
		o.services = svcs
		if len(o.services) == 0 {
			return fmt.Errorf("netstate: no enabled network services to configure")
		}
	}
	o.prev = make(map[string][]string, len(o.services))
	for _, svc := range o.services {
		got, err := sys.DNS().Configured(ctx, svc)
		if err != nil {
			return err
		}
		// notSelf: a captured resolver that is one of ours is the residue of a
		// run that died before it could restore anything, and restoring it would
		// leave the machine pointed at a resolver that is not listening. It is
		// only OUR residue when a previous run is known to have died, though —
		// otherwise 127.0.0.1 here is the user's own dnscrypt-proxy.
		o.prev[svc] = notSelfServers(got, o.servers, e.PriorResidue)
	}
	o.prepared = true
	return nil
}

func (o *dnsOp) Apply(ctx context.Context, e Env) error {
	dc := o.sys(e).DNS()
	for _, svc := range o.services {
		if err := dc.Set(ctx, svc, o.servers); err != nil {
			return err
		}
	}
	return nil
}

func (o *dnsOp) Verify(ctx context.Context, e Env) error {
	got, err := o.sys(e).DNS().Live(ctx)
	if err != nil {
		return err
	}
	if !hasPrefixList(got, o.servers) {
		return fmt.Errorf("scutil --dns reports nameservers %v, want them to start with %v", got, o.servers)
	}
	return nil
}

// hasPrefixList reports whether got starts with want.
func hasPrefixList(got, want []string) bool {
	if len(got) < len(want) {
		return false
	}
	for i, w := range want {
		if got[i] != w {
			return false
		}
	}
	return true
}

func (o *dnsOp) Revert(ctx context.Context, e Env) error {
	dc := o.sys(e).DNS()
	var firstErr error
	for _, svc := range o.services {
		var err error
		if prev := o.prev[svc]; len(prev) > 0 {
			err = dc.Set(ctx, svc, prev)
		} else {
			// Clear is the platform's way of saying "back to DHCP".
			err = dc.Clear(ctx, svc)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (o *dnsOp) VerifyReverted(ctx context.Context, e Env) error {
	sys := o.sys(e)
	got, err := sys.DNS().Live(ctx)
	if err != nil {
		return err
	}
	if hasPrefixList(got, o.servers) {
		return fmt.Errorf("scutil --dns still reports our nameservers %v", o.servers)
	}
	// scutil reports the primary service only, while Revert mutated every
	// service in o.services. Read the rest back so the verifier covers every
	// mutation instead of one of them.
	for _, svc := range o.services {
		stored, err := sys.DNS().Configured(ctx, svc)
		if err != nil {
			return err
		}
		if hasPrefixList(stored, o.servers) {
			return fmt.Errorf("networksetup still reports our nameservers %v on %s", o.servers, svc)
		}
	}
	return nil
}

func (o *dnsOp) Record() Record {
	raw, err := marshalRevert(dnsRevert{Servers: o.servers, Services: o.services, Prev: o.prev})
	rec := Record{Kind: OpDNSServers, ID: o.ID(), Revert: raw}
	if err != nil {
		rec.Note = err.Error()
	}
	return rec
}

func reviveDNS(r Record) (Op, error) {
	var p dnsRevert
	if err := unmarshalRevert(r.Revert, &p); err != nil {
		return nil, err
	}
	if len(p.Services) == 0 {
		return nil, fmt.Errorf("netstate: dns record lists no services")
	}
	if p.Prev == nil {
		p.Prev = map[string][]string{}
	}
	return &dnsOp{servers: p.Servers, services: p.Services, prev: p.Prev, prepared: true}, nil
}
