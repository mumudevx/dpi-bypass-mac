package sysport

import (
	"context"
	"errors"
	"net/netip"
)

// Port is everything an Op needs from the operating system.
type Port interface {
	Proxy() ProxyController
	DNS() DNSController
	Route() RouteController
	Iface() IfaceController
	Env() EnvController
	Facts() FactsCollector
	Caps() Caps
}

// RouteSpec names one route. It is the same value on every platform; only the
// mechanism that installs it differs.
//
//   - Gw valid, Iface set   → a gateway route scoped to Iface
//   - Gw valid, Iface empty → a plain gateway route
//   - Gw invalid, Iface set → an interface route
type RouteSpec struct {
	Dst   netip.Prefix
	Gw    netip.Addr
	Iface string
}

type RouteController interface {
	Add(ctx context.Context, s RouteSpec) error
	Delete(ctx context.Context, s RouteSpec) error
	// RIB is the independent verifier. It MUST NOT share a code path with Add
	// and Delete; see the package comment.
	RIB() RIBReader
}

// ProxyKind distinguishes the three proxy settings macOS treats separately.
type ProxyKind int

const (
	ProxyAuto ProxyKind = iota // PAC URL
	ProxyWeb                   // web + secure web, always set together
	ProxySOCKS
)

type ProxyController interface {
	// Services lists the network services a proxy may be set on. On Windows
	// this is a single pseudo-service; see scwindows.
	Services(ctx context.Context) ([]string, error)
	// Configured reads svc's stored settings through the same subsystem the
	// setters write to. This is for CAPTURE, never for verification.
	//
	// kinds narrows the read to the settings the caller actually intends to
	// restore. That is not an optimisation: reading a kind the caller does not
	// need means a getter that fails for an unrelated setting aborts the whole
	// apply. Passing no kinds reads all of them, which only a caller that
	// genuinely wants the whole service should do.
	Configured(ctx context.Context, svc string, kinds ...ProxyKind) (ProxySettings, error)
	SetAuto(ctx context.Context, svc, url string) error
	SetManual(ctx context.Context, svc string, kind ProxyKind, host string, port int) error
	// Restore puts svc back to prev. It MUST refuse a prev whose Kinds is
	// empty — see ProxySettings.CheckRestorable — rather than reading it as
	// "all", which is the reading Configured gives it.
	//
	// The asymmetry is the point. Configured with no kinds READS everything,
	// and an over-wide read costs a few getters. Restore with no kinds would
	// WRITE everything, so a zero-value ProxySettings — the value a caller
	// gets from a struct it forgot to fill in — switches off every proxy on
	// the service, including ones this tool never touched.
	Restore(ctx context.Context, svc string, prev ProxySettings) error
	// Live reads the system's RESOLVED proxy configuration through a DIFFERENT
	// subsystem than the setters write to. This is the verifier.
	Live(ctx context.Context) (ProxyState, error)
}

type DNSController interface {
	// Configured reads one service's stored resolvers (capture).
	Configured(ctx context.Context, svc string) ([]string, error)
	Set(ctx context.Context, svc string, servers []string) error
	// Clear restores svc to DHCP-supplied resolvers.
	Clear(ctx context.Context, svc string) error
	// Live reads the resolvers the system actually consults (verify).
	Live(ctx context.Context) ([]string, error)
}

// IfaceConfig is the state a tunnel device should be in. It is one value
// because macOS reaches it in one ifconfig invocation; a platform that needs
// several calls makes them behind Configure.
type IfaceConfig struct {
	Local string
	// Peer is the v4 point-to-point peer: a utun has no link layer, so without
	// a destination the kernel has nothing to attach the interface route to. It
	// is empty for IPv6, where macOS takes a prefix length instead.
	//
	// There is no family field. The family is derived from Local — an address
	// with a colon in it is v6 — because a flag beside the address could
	// disagree with it, and the address is the thing the kernel is given.
	Peer string
	MTU  int
}

type IfaceController interface {
	// Configure brings iface to cfg. macOS emits a single ifconfig carrying
	// address, peer or prefixlen, MTU and up — splitting that into separate
	// calls would change the argv the kernel sees.
	Configure(ctx context.Context, iface string, cfg IfaceConfig) error
	// Unconfigure removes the address Configure added. It deliberately does not
	// bring the interface down: a utun belongs to whoever holds its file
	// descriptor and vanishes when they close it, and downing anything else
	// would be catastrophic.
	Unconfigure(ctx context.Context, iface string, cfg IfaceConfig) error
	// Addrs reads an interface's addresses back through a different subsystem
	// than Configure wrote through (verify).
	Addrs(ctx context.Context, iface string) ([]netip.Addr, error)
}

type EnvController interface {
	// Get is the CAPTURE read: it answers "what is this variable's value, and
	// is it set at all", and a read that could not establish that is an ERROR,
	// never a "no".
	//
	// The distinction is destructive, not academic. launchEnvOp records the
	// answer in prevSet, and Revert UNSETS every name it recorded as unset — so
	// a Get that reports "not set" when it merely failed to look deletes the
	// user's own HTTPS_PROXY on the way out. Refusing the apply is what this
	// tool shipped with (46e30d6, op_launchenv.go:105) and the only safe answer
	// for a value a later write restores from.
	//
	// A failure that says nothing at all is still a failure here; it is
	// reported wrapping ErrEnvUnreadable so that EnvLookup — and only
	// EnvLookup — can choose to read it as "not set".
	Get(ctx context.Context, name string) (string, bool, error)
	Set(ctx context.Context, name, value string) error
	Unset(ctx context.Context, name string) error
}

// ErrEnvUnreadable marks a variable whose value could not be established
// because the read failed WITHOUT saying why: some launchd builds answer
// `launchctl getenv NAME` for an unset variable by exiting non-zero and
// printing nothing, which is byte-for-byte what a failed read looks like.
//
// An implementation reports it rather than deciding, because the two callers
// want opposite answers to the same ambiguity. See EnvLookup.
var ErrEnvUnreadable = errors.New("netstate: the variable could not be read")

// EnvLookup is the DIAGNOSTIC read, and the one place ErrEnvUnreadable is
// tolerated: `dpb doctor` and `dpb coverage` ask "is this variable set", and a
// diagnostic line that says "could not tell" where it could say "no" is one
// nobody can act on.
//
// The asymmetry with EnvController.Get is deliberate and is the whole point of
// having two readers: a diagnostic only PRINTS its answer, while a capture
// feeds a Revert that WRITES. Guessing costs a wrong word in one and the user's
// pre-existing environment in the other.
func EnvLookup(ctx context.Context, ec EnvController, name string) (string, error) {
	v, _, err := ec.Get(ctx, name)
	if errors.Is(err, ErrEnvUnreadable) {
		return "", nil
	}
	return v, err
}

type FactsCollector interface {
	// Collect reads the machine's network identity. selfIface names the tunnel
	// THIS run owns, or "" before we have one — classifyVPN needs it because our
	// own capture routes are indistinguishable from a full-tunnel VPN's.
	Collect(ctx context.Context, selfIface string) (*Facts, error)
}

// Caps is the system-mutation analogue of strategy.Cap. A capability a platform
// lacks is refused BY NAME AND WITH A REASON, never skipped quietly — the rule
// emit/stub_other.go states for wire techniques, applied to system state.
type Caps uint32

const (
	CapProxyAuto   Caps = 1 << iota // can point the system at a PAC URL
	CapProxyManual                  // can set an explicit host:port proxy
	CapDNSOverride                  // can replace the system resolvers
	CapRouteWrite                   // can add and delete routes
	CapIfaceConfig                  // can address and MTU a tunnel device
	CapSessionEnv                   // can set a login-session environment variable
	CapPerService                   // system state is per network service, not global
)

func (c Caps) Has(want Caps) bool     { return c&want == want }
func (c Caps) Missing(want Caps) Caps { return want &^ c }
