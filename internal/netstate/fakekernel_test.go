//go:build darwin

package netstate

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/mumudevx/dpb/internal/sysconf/scdarwin"
)

// runnerFunc is a Runner from a function. lock_test.go drives `ps` through it;
// it left this package with services_test.go, which had nothing to do with the
// run lock, and comes back beside the other helpers the fake needs.
type runnerFunc func(ctx context.Context, name string, args ...string) Result

func (f runnerFunc) Run(ctx context.Context, name string, args ...string) Result {
	return f(ctx, name, args...)
}

// fakeSystem models a whole macOS: it answers the tools, and it implements
// RIBReader over the same in-memory routes those tools mutate. That single
// source of truth is what makes the chaos table meaningful, and it is why the
// fake stays here after the tool calls moved to scdarwin — roughly sixty tests
// in this package drive their Ops through it, and an Op still reaches the
// system through a Port built from that same Runner.
//
// Three helpers the fake needs went with the implementation. Go cannot share an
// unexported symbol across a package boundary, so they are here in test-only
// code rather than exported from scdarwin for a fake's benefit — the trade
// Task 2 already made when it duplicated sysport's fixture() helper and its
// testdata. NCService is exported over there, so it is aliased rather than
// copied; the other three are small and pure, and a divergence between the
// fake's answers and the kernel reader's would be a real disagreement about
// what macOS does rather than an accident of transcription.

// NCService is one entry from `scutil --nc list`, the type the fake's VPN list
// is written in.
type NCService = scdarwin.NCService

// pickDefault finds the unscoped default when iface is empty, or the
// interface-scoped default for iface when it is not. IPv4 wins over IPv6
// because callers use it to identify the uplink, and on a dual-stack macOS box
// the v4 default is the one that names the physical service.
func pickDefault(rs []RouteEntry, iface string) (RouteEntry, bool, error) {
	var v6 RouteEntry
	var haveV6 bool
	for _, r := range rs {
		if r.Dst.Bits() != 0 {
			continue
		}
		if iface == "" {
			if r.Scoped {
				continue
			}
		} else if !r.Scoped || r.Iface != iface {
			continue
		}
		if r.Dst.Addr().Is4() {
			return r, true, nil
		}
		if !haveV6 {
			v6, haveV6 = r, true
		}
	}
	return v6, haveV6, nil
}

func routeExists(rs []RouteEntry, dst netip.Prefix, iface string) bool {
	want := dst.Masked()
	for _, r := range rs {
		if r.Dst != want {
			continue
		}
		if iface == "" || r.Iface == iface {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
