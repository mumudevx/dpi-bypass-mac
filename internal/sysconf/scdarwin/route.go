//go:build darwin

package scdarwin

import (
	"context"

	"github.com/mumudevx/dpb/internal/sysport"
)

// routeCtl writes routes with route(8) and hands out an AF_ROUTE reader to
// verify them.
//
// This is the controller the whole "do not believe your tools" rule was written
// for. macOS route(8) cannot report failure through its exit status: Apple's
// route.c declares newroute() void and main() does `newroute(argc, argv);
// exit(0)`, and rtmsg() only warnx()es. Verified 2026-09-02:
// `route -n get -inet6 2001:db8::1` prints "route: writing to routing socket:
// not in table" and exits 0. Result.Failed() catches that on the way out, and
// the RIB read catches everything Result.Failed() does not.
type routeCtl struct{ p *port }

var _ sysport.RouteController = routeCtl{}

func (c routeCtl) Add(ctx context.Context, s sysport.RouteSpec) error {
	return c.p.run.Run(ctx, "route", routeArgs(s, "add")...).Error()
}

// Delete issues the delete and reports what route(8) said. The caller decides
// what that means: "not in table" is both the normal answer for an
// already-absent route and, per the liar table, a failure, and only a RIB read
// can tell the two apart.
func (c routeCtl) Delete(ctx context.Context, s sysport.RouteSpec) error {
	return c.p.run.Run(ctx, "route", routeArgs(s, "delete")...).Error()
}

// RIB is the independent verifier: route(8) writes, an AF_ROUTE socket reads,
// and the two never share a code path.
func (c routeCtl) RIB() sysport.RIBReader { return c.p.rib }

// routeArgs builds the route(8) argv for verb ("add" or "delete"). -n keeps
// route from doing reverse DNS, which on a censored line can block for seconds.
func routeArgs(s sysport.RouteSpec, verb string) []string {
	args := []string{"-n", verb}
	if s.Dst.Addr().Is4() {
		args = append(args, "-inet")
	} else {
		args = append(args, "-inet6")
	}
	if s.Dst.Bits() == 0 {
		// route(8) will not accept 0.0.0.0/0 as a -net argument.
		args = append(args, "default")
	} else {
		args = append(args, "-net", s.Dst.String())
	}
	switch {
	case s.Gw.IsValid():
		args = append(args, s.Gw.String())
		if s.Iface != "" {
			args = append(args, "-ifscope", s.Iface)
		}
	case s.Iface != "":
		args = append(args, "-interface", s.Iface)
	}
	return args
}
