package netwatch

import (
	"errors"
	"fmt"

	"github.com/mumudevx/dpb/internal/netstate"
)

// ErrFullTunnelVPN is the refuse-for-safety exit: a VPN owns the whole address
// space and this run needs to capture traffic, so nothing we install can carry
// a packet. cliapp maps it to exit code 5.
//
// It is an error rather than a warning because the alternative is the exact
// failure docs/PLAN.md's verification contract exists to prevent: printing
// "Ready" while capturing nothing. A user who believes dpb is bypassing, and
// is not, keeps sending plain ClientHellos at a DPI that is blocking them, and
// learns about it from a website that does not load rather than from us.
var ErrFullTunnelVPN = errors.New(
	"a full-tunnel VPN owns the default route, so dpb's capture routes cannot carry traffic")

// VPNVerdict is what netwatch decides about a VPN, given what netstate saw.
type VPNVerdict struct {
	Present     bool
	FullTunnel  bool
	Iface       string
	ServiceName string
	// Fatal says this run cannot continue. It is FullTunnel && RequireCapture,
	// and nothing else: a full tunnel under a loopback proxy is fine, and a
	// split tunnel is fine under either front end.
	Fatal  bool
	Err    error
	Detail string
}

// ClassifyVPN turns netstate's observation into this run's policy.
//
// The observation itself belongs to netstate.CollectFacts and is deliberately
// not repeated here. It reads the routing table ONCE and looks for two shapes:
// an unscoped default owned by a tunnel interface, and the 0.0.0.0/1 +
// 128.0.0.0/1 (or ::/1 + 8000::/1) half-default pair that wg-quick, Tailscale
// and Mullvad install instead of a default so that tearing the tunnel down
// does not cost the machine its gateway. The wave 1 review found that missing
// the half-default idiom left the safety gate silent for the most common macOS
// full tunnel there is — and those tools do not appear in `scutil --nc list`
// either, so the second signal is silent at the same time. Splitting the
// observation from the policy is what keeps that in one place: netwatch asks
// the same question on every network change that start-up asked once.
//
// requireCapture is true only for a front end whose correctness depends on
// owning routes — TUN mode. A proxy on loopback keeps working underneath any
// VPN, full tunnel included, because the browser reaches 127.0.0.1 without
// consulting the routing table's default at all.
func ClassifyVPN(f *netstate.Facts, requireCapture bool) VPNVerdict {
	var v VPNVerdict
	if f == nil {
		return v
	}
	v.Present = f.VPN.Present
	v.FullTunnel = f.VPN.FullTunnel
	v.Iface = f.VPN.Iface
	v.ServiceName = f.VPN.ServiceName

	switch {
	case !v.Present:
		return v
	case !v.FullTunnel:
		// A split tunnel routes some prefixes and leaves the default alone, so
		// our scoped uplink default and our capture routes both still work.
		// This is the case a rollback must never touch: the VPN's routes are
		// Adopted, and reverting them would take the user's corporate network
		// away as a side effect of Ctrl-C.
		v.Detail = fmt.Sprintf("a split-tunnel VPN (%s) is up; its routes are left alone",
			nameOr(v.ServiceName, v.Iface))
		return v
	case !requireCapture:
		// Worth saying out loud even though it changes nothing: a user whose
		// traffic is already leaving through a VPN is measuring that network's
		// censor, not their ISP's, and the verdict namespace says so (the
		// NetworkID's Kind is "vpn").
		v.Detail = fmt.Sprintf("a full-tunnel VPN (%s) owns the default route; "+
			"the proxy still works, but every verdict learned now describes the VPN's "+
			"exit network and not this ISP", nameOr(v.ServiceName, v.Iface))
		return v
	default:
		v.Fatal = true
		v.Err = fmt.Errorf("%w (interface %s)", ErrFullTunnelVPN, nameOr(v.Iface, v.ServiceName))
		v.Detail = fmt.Sprintf("a full-tunnel VPN (%s) took the default route; "+
			"dpb is stopping rather than reporting success while capturing nothing",
			nameOr(v.ServiceName, v.Iface))
		return v
	}
}

func nameOr(a, b string) string {
	if a != "" {
		return a
	}
	if b != "" {
		return b
	}
	return "unnamed"
}
