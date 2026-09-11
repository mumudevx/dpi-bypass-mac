package netstate

import (
	"context"
	"fmt"
	"net/netip"
)

func init() { reviveByKind[OpRoute] = reviveRoute }

type routeRevert struct {
	Dst   string `json:"dst"`
	Gw    string `json:"gw,omitempty"`
	Iface string `json:"iface,omitempty"`
}

// routeOp adds one kernel route through the Port and verifies it by reading the
// RIB, which is a different subsystem on every platform we implement.
//
// This is the Op the whole "do not believe your tools" rule was written for.
// macOS route(8) cannot report failure through its exit status: Apple's
// route.c declares newroute() void and main() does `newroute(argc, argv);
// exit(0)`, and rtmsg() only warnx()es. Verified 2026-09-02:
// `route -n get -inet6 2001:db8::1` prints "route: writing to routing socket:
// not in table" and exits 0. Result.Failed() catches that on the way out, and
// the RIB read catches everything Result.Failed() does not.
type routeOp struct {
	run   Runner
	dst   netip.Prefix
	gw    netip.Addr
	iface string

	// added records that our own `route add` reported success, i.e. that this
	// Op is responsible for whatever now sits at dst. It is false for an Op
	// rebuilt from a journal record, which is correct: Manager.rollback is the
	// only caller of mutated(), and a revived Op is reverting a change a dead
	// process made.
	added bool
}

// NewRoute returns an Op installing a route to dst.
//
//   - gw valid, iface set   → a gateway route scoped to iface (-ifscope)
//   - gw valid, iface empty → a plain gateway route
//   - gw invalid, iface set → an interface route (-interface), which is how the
//     capture routes are installed and why they vanish with the utun
func NewRoute(r Runner, dst netip.Prefix, gw netip.Addr, iface string) Op {
	return &routeOp{run: r, dst: dst.Masked(), gw: gw, iface: iface}
}

func (o *routeOp) Kind() OpKind { return OpRoute }

func (o *routeOp) ID() string {
	if o.iface != "" {
		return fmt.Sprintf("route:%s@%s", o.dst, o.iface)
	}
	return fmt.Sprintf("route:%s", o.dst)
}

func (o *routeOp) Describe() string {
	switch {
	case o.gw.IsValid() && o.iface != "":
		return fmt.Sprintf("add route %s via %s scoped to %s", o.dst, o.gw, o.iface)
	case o.gw.IsValid():
		return fmt.Sprintf("add route %s via %s", o.dst, o.gw)
	default:
		return fmt.Sprintf("add route %s via interface %s", o.dst, o.iface)
	}
}

func (o *routeOp) runner(e Env) Runner {
	if o.run != nil {
		return o.run
	}
	return e.runner()
}

// sys is the Port this Op mutates through. An Op carries its own Runner —
// NewRoute takes one — so the Port has to be built from that rather than from
// the Env's, or a caller who passed a Runner to the constructor would find the
// mutation going somewhere else.
//
// The precedence, stated because the assignment below hides it: Env.sys()
// returns e.Sys whenever the caller set one and NEVER consults Runner in that
// case (manager.go:62). A Port beats a Runner. cliapp sets Sys on every Env it
// hands an Op (root.go:222), so in the shipped configuration this assignment
// decides nothing at all.
//
// It stays anyway, and not out of caution: it is what decides for an Env that
// carries a Runner and no Port, which is how most of this package's tests and
// any embedder written before Env.Sys existed construct one. Deleting it would
// silently reroute those from the Op's Runner to the Env's — a change in which
// runner wins, which is a semantic change rather than a cleanup.
func (o *routeOp) sys(e Env) Port {
	env := e
	env.Runner = o.runner(e)
	return env.sys()
}

// spec is what the route is, independent of how a platform installs it.
func (o *routeOp) spec() RouteSpec {
	return RouteSpec{Dst: o.dst, Gw: o.gw, Iface: o.iface}
}

func (o *routeOp) Apply(ctx context.Context, e Env) error {
	// The error is checked, but it is only the first line of defence: Verify
	// reading the RIB is the one that decides.
	o.added = false
	if err := o.sys(e).Route().Add(ctx, o.spec()); err != nil {
		return err
	}
	o.added = true
	return nil
}

// mutated tells Manager.rollback whether there is anything to undo. A failed
// add created nothing — the common shape is the exit-0 "File exists" liar,
// which means the destination was already owned by somebody else — and issuing
// the delete anyway would remove their route, not ours.
func (o *routeOp) mutated() bool { return o.added }

// canAdopt is TRUE, and routeOp is the only Op in this package for which it is.
// It is spelled out rather than left to canAdopt()'s default because on Windows
// the default is load bearing, and an invisible default is not a decision the
// next person can find.
//
// proxyOp, dnsOp, pacFileOp and launchEnvOp all return false: the only way
// their Verify can pass before Apply is by finding OUR OWN settings already in
// place, which means a previous run was SIGKILLed, and adopting that residue
// would make it permanent. A route is the other case. A row already in the
// kernel routing table with our destination, our interface, our next hop and
// our scope is state the machine had before we arrived; the honest answer is to
// touch it once (to read it) and never again.
//
// Two concrete things depend on that, and they are different:
//
//   - macOS: a coexisting VPN's `-ifscope` default. Adoption is what stops
//     Ctrl-C from deleting it — Record.Adopted, honoured by Manager.UndoAll.
//
//   - Windows: the uplink default tunfe installs before the capture routes
//     (front/tunfe/stack.go, BringUp). Windows has no RTF_IFSCOPE, so there is
//     no second row to create — the "scoped" default IS the machine's own
//     default. sysconf/scwindows/rib.go defines RouteEntry.Scoped as "this row
//     has a next hop", and sysconf/scwindows/facts.go reads Facts.Uplink and
//     Facts.Gateway out of that very row (`f.Uplink, f.Gateway = def.Iface,
//     def.Gateway`), which is what cliapp then puts in Capture.Uplink and
//     Capture.Gateway. So the RouteSpec tunfe asks for and the row matchRoute
//     finds are THE SAME ROW: Verify passes before Apply, the Op is adopted,
//     CreateIpForwardEntry2 is never called, and teardown deletes nothing.
//     Windows' ERROR_OBJECT_ALREADY_EXISTS is not reached on that path at all.
//
// What this does NOT do is swallow the other collision, and the discriminator
// is matchRoute rather than anything written here. matchRoute compares
// destination AND interface AND next hop AND Scoped, so a capture route that
// collides with somebody else's route — a coexisting tunnel's 0.0.0.0/1, a
// stale row on a reused adapter with a next hop ours does not have — does not
// match on those four, is NOT adopted, and goes to Apply. The Add then fails,
// mutated() stays false, and Manager.rollback issues no delete. That is exactly
// what Plan 3 made ERROR_OBJECT_ALREADY_EXISTS an error for (see
// sysconf/scwindows/route.go, routeCtl.Add), and it is untouched.
func (o *routeOp) canAdopt() bool { return true }

func (o *routeOp) Verify(ctx context.Context, e Env) error {
	rs, err := o.routes(e)
	if err != nil {
		return err
	}
	if !matchRoute(rs, o.dst, o.gw, o.iface, o.gw.IsValid() && o.iface != "") {
		return fmt.Errorf("route %s is absent from the kernel routing table", o.Describe())
	}
	return nil
}

func (o *routeOp) routes(e Env) ([]RouteEntry, error) {
	if e.RIB == nil {
		return nil, fmt.Errorf("netstate: no RIB reader configured; cannot verify routes")
	}
	rs, err := e.RIB.Routes()
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// matchRoute looks for an entry the mutation would have created. A scoped route
// must actually carry the scope flag: an -ifscope add that silently landed as
// an unscoped route is the exact failure that lets a run report "Ready" while
// capturing nothing.
func matchRoute(rs []RouteEntry, dst netip.Prefix, gw netip.Addr, iface string, wantScoped bool) bool {
	want := dst.Masked()
	for _, r := range rs {
		if r.Dst != want {
			continue
		}
		if iface != "" && r.Iface != iface {
			continue
		}
		if gw.IsValid() && !sameGateway(r.Gateway, gw) {
			continue
		}
		// RTF_IFSCOPE is part of the route's identity, not a detail: a scoped
		// entry does not satisfy an unscoped request (we would report success
		// having installed nothing) and an unscoped entry does not satisfy a
		// scoped one (VerifyReverted would match a sibling forever).
		if r.Scoped != wantScoped {
			continue
		}
		return true
	}
	return false
}

// sameGateway compares next hops ignoring the IPv6 zone, because route(8) is
// given an unzoned address while the RIB reports the zone the kernel attached.
func sameGateway(a, b netip.Addr) bool {
	return a.WithZone("").Unmap() == b.WithZone("").Unmap()
}

// Revert deletes the route. A failed delete is logged, never returned:
// "not in table" is both the normal answer for an already-absent route and,
// per the liar table, a failure. Only VerifyReverted reading the RIB can tell
// the two apart, so that is what decides.
func (o *routeOp) Revert(ctx context.Context, e Env) error {
	// Look before deleting. The kernel resolves RTM_DELETE by destination +
	// netmask + explicit -ifscope; the link gateway that `-interface` supplies
	// is never compared, so `route delete -net 0.0.0.0/1 -interface utunOURS`
	// removes whatever owns 0.0.0.0/1 on ANY interface. If the RIB says the
	// entry there is not ours, it belongs to a coexisting tunnel and we leave
	// it alone. A RIB we cannot read is the one case where we still issue the
	// delete: VerifyReverted is what decides, and refusing outright would strand
	// our own capture route.
	if rs, err := o.routes(e); err == nil {
		if !matchRoute(rs, o.dst, o.gw, o.iface, o.gw.IsValid() && o.iface != "") {
			e.logf("netstate: %s is not in the routing table on our own interface; leaving whatever owns %s alone",
				o.ID(), o.dst)
			return nil
		}
	} else {
		e.logf("netstate: cannot read the RIB before deleting %s (%v); issuing the delete and letting VerifyReverted decide",
			o.ID(), err)
	}
	if err := o.sys(e).Route().Delete(ctx, o.spec()); err != nil {
		e.logf("netstate: route delete reported %q; the RIB read decides", err)
	}
	return nil
}

func (o *routeOp) VerifyReverted(ctx context.Context, e Env) error {
	rs, err := o.routes(e)
	if err != nil {
		return err
	}
	if matchRoute(rs, o.dst, o.gw, o.iface, o.gw.IsValid() && o.iface != "") {
		return fmt.Errorf("route %s is still in the kernel routing table", o.Describe())
	}
	return nil
}

func (o *routeOp) Record() Record {
	rev := routeRevert{Dst: o.dst.String(), Iface: o.iface}
	if o.gw.IsValid() {
		rev.Gw = o.gw.String()
	}
	raw, err := marshalRevert(rev)
	rec := Record{Kind: OpRoute, ID: o.ID(), Revert: raw}
	if err != nil {
		rec.Note = err.Error()
	}
	return rec
}

func reviveRoute(r Record) (Op, error) {
	var p routeRevert
	if err := unmarshalRevert(r.Revert, &p); err != nil {
		return nil, err
	}
	dst, err := netip.ParsePrefix(p.Dst)
	if err != nil {
		return nil, fmt.Errorf("netstate: route record has unparseable destination %q: %w", p.Dst, err)
	}
	op := &routeOp{dst: dst.Masked(), iface: p.Iface}
	if p.Gw != "" {
		gw, err := netip.ParseAddr(p.Gw)
		if err != nil {
			return nil, fmt.Errorf("netstate: route record has unparseable gateway %q: %w", p.Gw, err)
		}
		op.gw = gw
	}
	return op, nil
}
