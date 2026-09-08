package sysport

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// RouteEntry is one kernel routing table entry, reduced to the fields we
// actually make decisions on.
type RouteEntry struct {
	Dst     netip.Prefix
	Gateway netip.Addr
	Iface   string
	Index   int
	// Scoped is true for a route carrying RTF_IFSCOPE — macOS's per-interface
	// scoping. A VPN's scoped default lives here, and recognising it is what
	// stops us from deleting someone's VPN on Ctrl-C.
	Scoped bool
}

func (r RouteEntry) String() string {
	gw := "-"
	if r.Gateway.IsValid() {
		gw = r.Gateway.String()
	}
	s := fmt.Sprintf("%s via %s dev %s(%d)", r.Dst, gw, r.Iface, r.Index)
	if r.Scoped {
		s += " scoped"
	}
	return s
}

// RIBReader reads the kernel routing table directly through an AF_ROUTE socket.
// It is the independent verifier for every route mutation: route(8) writes,
// this reads, and the two never share a code path.
//
// Verified openable unprivileged on this machine: FetchRIB returned 19808 bytes
// / 121 messages as uid 501.
type RIBReader interface {
	Routes() ([]RouteEntry, error)
	Default() (RouteEntry, bool, error)
	ScopedDefault(iface string) (RouteEntry, bool, error)
	Exists(dst netip.Prefix, iface string) (bool, error)
}

// ProxyState is `scutil --proxy` reduced to a lookup table. scutil prints a
// flat CFDictionary with one nested array, so a map plus the exceptions list is
// a complete representation.
type ProxyState struct {
	Keys       map[string]string
	Exceptions []string
}

// Str returns the value for key, or "" if absent.
func (p ProxyState) Str(key string) string { return p.Keys[key] }

// On reports whether an scutil boolean key ("0"/"1") is set.
func (p ProxyState) On(key string) bool { return p.Keys[key] == "1" }

// Int returns the value for key as an integer; ok is false if absent or
// unparseable.
func (p ProxyState) Int(key string) (int, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(p.Keys[key]))
	if err != nil {
		return 0, false
	}
	return v, true
}

// VPNState describes whether a VPN is in the way. FullTunnel is the one that
// changes behaviour: if something else owns the unscoped default route, our
// capture routes and our scoped uplink default cannot be made to work, and the
// honest answer is to stop rather than report success.
type VPNState struct {
	Present     bool
	FullTunnel  bool
	Iface       string
	ServiceName string
}

// Facts is the snapshot of the machine's network identity that every mutation
// is planned against. It is a value, collected once per network change, so a
// mid-run reconfiguration cannot make two Ops disagree about which interface
// the uplink is.
type Facts struct {
	Uplink  string
	Gateway netip.Addr
	// UplinkV6 and GatewayV6 are the machine's real IPv6 next hop, read the
	// same way and kept separate because they are frequently a different
	// interface — or absent entirely on a v4-only line. TUN mode needs them to
	// scope an IPv6 default to the uplink before ::/1 and 8000::/1 point at the
	// tunnel; without that route our own upstream v6 sockets would be pulled
	// back into our own netstack and loop.
	UplinkV6    string
	GatewayV6   netip.Addr
	UplinkMAC   string
	V4Global    []netip.Addr
	V6Global    []netip.Addr
	Services    []string
	VPN         VPNState
	CollectedAt time.Time
}

// ProxySettings is one service's stored proxy configuration — the writer's own
// view of it, used to capture what must be restored later.
type ProxySettings struct {
	// Kinds names the settings this value actually describes; nil means all of
	// them, which is what Configured returns.
	//
	// It exists because a capture is not always whole-service. An Op that set a
	// PAC URL read `networksetup -getautoproxyurl` and nothing else, so its
	// captured web/secure/SOCKS fields are zero because they were never asked
	// about — not because the user has no web proxy. A Restore that could not
	// tell those apart would issue `-setwebproxy <svc> "" 0` on the way out and
	// switch off a proxy this Op never touched, which is precisely what happens
	// when a PAC Op and a web-proxy Op are reverted in sequence: the second
	// revert undoes the first. It would also run six more networksetup
	// invocations against the user's configuration than the mutation needed.
	Kinds      []ProxyKind
	AutoURL    string
	AutoOn     bool
	WebHost    string
	WebPort    int
	WebOn      bool
	SecureHost string
	SecurePort int
	SecureOn   bool
	SOCKSHost  string
	SOCKSPort  int
	SOCKSOn    bool
}
