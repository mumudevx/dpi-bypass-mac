// Package policy answers one question for every flow: may dpb touch this, and
// if so, how.
//
// The architecture it encodes is MEASUREMENTS.md §5.2. Ten of the 41 hosts
// probed on the measured line — every Turkish bank and every .gov.tr site
// tested — break under the emitter that defeats the DPI, and §5.1 concludes
// that "no emitter is both a bypass and universally safe". A shipped exclusion
// list therefore cannot be the defence: 24% of hosts are fragile and no
// hand-maintained list covers the Turkish long tail.
//
// So the default verdict on an inspected port is ScopeWatch — send the first
// message unmodified and escalate only on evidence — and everything in this
// package exists to make that default cheap, durable and explainable:
//
//   - Matcher, the label-anchored rule matcher, so a bypass for bank.com can
//     never be claimed by evilbank.com.
//   - IPSet, the same for IP-literal flows, with the bogon table compiled in.
//   - NetworkID, so a verdict learned on home WiFi is never replayed on a
//     hotspot behind a different censor.
//   - Store, the durable per-network verdict cache, written atomically.
//   - ReverseMap, so a TUN flow to a bare IP can be named from the DNS answer
//     we ourselves served.
//   - Singleflight, so the six connections a browser opens walk the ladder once.
//   - Explanation, so `dpb why` can show the user exactly which rule decided.
package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// ScopeClass is the decision made about a flow before any byte is read.
type ScopeClass uint8

const (
	// ScopeBypass is a hard veto: the flow is never buffered and never
	// desynced. Reserved for names and addresses we have positive evidence
	// about (the measured regressors, RFC1918) and for anything the user
	// bypassed by hand.
	ScopeBypass ScopeClass = iota
	// ScopeDirect relays immediately with no first-message buffering. Used for
	// ports we do not inspect, for hosts already known to work plain, and for
	// the whole world while a captive portal or `dpb off` is in force.
	ScopeDirect
	// ScopeWatch is the DEFAULT for every inspect port: buffer the complete
	// first message, send it UNMODIFIED, and escalate the ladder only on
	// RST/EOF before any upstream byte reaches the client. MEASUREMENTS.md
	// §5.2 calls this a correctness requirement, not an optimisation.
	ScopeWatch
	// ScopeDesync means a cached or probed winner exists; apply it on attempt
	// one.
	ScopeDesync
)

var scopeClassNames = [...]string{"bypass", "direct", "watch", "desync"}

func (c ScopeClass) String() string {
	if int(c) < len(scopeClassNames) {
		return scopeClassNames[c]
	}
	return fmt.Sprintf("scopeclass(%d)", uint8(c))
}

// MarshalText makes a persisted verdict survive a reordering of the constants
// above. The store is on disk for seven days; an iota shuffle in a later
// release must not silently reinterpret a cached "bypass" as "desync".
func (c ScopeClass) MarshalText() ([]byte, error) {
	if int(c) >= len(scopeClassNames) {
		return nil, fmt.Errorf("policy: unknown ScopeClass %d", uint8(c))
	}
	return []byte(scopeClassNames[c]), nil
}

func (c *ScopeClass) UnmarshalText(b []byte) error {
	s := string(b)
	for i, n := range scopeClassNames {
		if n == s {
			*c = ScopeClass(i)
			return nil
		}
	}
	return fmt.Errorf("policy: unknown ScopeClass %q", s)
}

// Source records why a verdict holds, so `dpb why` can attribute it.
type Source uint8

const (
	SrcBuiltinBypass Source = iota
	SrcUserBypass
	SrcUserInclude
	SrcProbed
	SrcLearnedDesync
	SrcLearnedPlain
	SrcDefault
)

var sourceNames = [...]string{
	"builtin-bypass",
	"user-bypass",
	"user-include",
	"probed",
	"learned-desync",
	"learned-plain",
	"default",
}

func (s Source) String() string {
	if int(s) < len(sourceNames) {
		return sourceNames[s]
	}
	return fmt.Sprintf("source(%d)", uint8(s))
}

func (s Source) MarshalText() ([]byte, error) {
	if int(s) >= len(sourceNames) {
		return nil, fmt.Errorf("policy: unknown Source %d", uint8(s))
	}
	return []byte(sourceNames[s]), nil
}

func (s *Source) UnmarshalText(b []byte) error {
	t := string(b)
	for i, n := range sourceNames {
		if n == t {
			*s = Source(i)
			return nil
		}
	}
	return fmt.Errorf("policy: unknown Source %q", t)
}

// Verdict is the complete decision for one (network, host, port).
type Verdict struct {
	Class    ScopeClass
	Spec     string
	Ladder   []string
	Source   Source
	Reason   string
	RuleText string
	RuleFrom string // provenance, e.g. "compiled-in" or "~/.config/dpb/config.toml:31"
	Learned  time.Time
	Expires  time.Time // zero means never
	Wins     int
	Losses   int
}

// Expired reports whether a learned verdict has aged out. A zero Expires never
// expires: MEASUREMENTS.md §5.2 wants "plain works" cached as durably as a
// desync winner, and it is self-revalidating at zero cost because a plain flow
// that starts failing simply escalates again.
func (v Verdict) Expired(now time.Time) bool {
	return !v.Expires.IsZero() && now.After(v.Expires)
}

// FromCompiledIn is the provenance string for rules baked into the binary. The
// Engine reads it to distinguish SrcBuiltinBypass from SrcUserBypass, so Rule
// needs no extra field and config can stay the single owner of the rule list.
const FromCompiledIn = "compiled-in"

// Rule is one scoping rule with its provenance, so `dpb why` can print the
// file and line that decided a flow's fate.
type Rule struct {
	Pattern string
	Class   ScopeClass
	From    string
	Line    int
}

// Where renders the provenance the way `dpb why` prints it.
func (r Rule) Where() string {
	switch {
	case r.From == "":
		return "unknown"
	case r.Line > 0:
		return fmt.Sprintf("%s:%d", r.From, r.Line)
	default:
		return r.From
	}
}

func (r Rule) source() Source {
	switch {
	case r.From == FromCompiledIn && r.Class == ScopeBypass:
		return SrcBuiltinBypass
	case r.Class == ScopeBypass, r.Class == ScopeDirect:
		return SrcUserBypass
	default:
		return SrcUserInclude
	}
}

// ConnSummary is one recent connection outcome, shown by `dpb why` so a user
// can see the decision and its consequences side by side.
type ConnSummary struct {
	At       time.Time
	Spec     string
	Attempts int
	OK       bool
	Latency  time.Duration
}

// Explanation is the full decision chain for one host.
type Explanation struct {
	Input     string
	Punycode  string
	Matched   []Rule
	Effective Verdict
	Recent    []ConnSummary
}

// Scope is the interface the front ends and the ladder runner consult. It is
// deliberately narrow: two lookups on the hot path and one diagnostic.
type Scope interface {
	ForName(host string, port int) Verdict
	ForAddr(ap netip.AddrPort) Verdict
	Explain(host string) Explanation
}

// defaultInspectPorts is MEASUREMENTS.md §1: the measured block is SNI-keyed on
// 443, and port 80 carries the Host-header mutators.
var defaultInspectPorts = []int{443, 80}

// EngineOptions configures the shipped Scope implementation. Everything is
// injected — clock, rules, store, network identity — because the whole point of
// this package is that its decisions are testable without a network.
type EngineOptions struct {
	// Rules are the name rules. Each carries its own ScopeClass, so the same
	// matcher holds --bypass (ScopeBypass) and --include (ScopeWatch) entries.
	Rules *Matcher
	// IPs are the address rules for IP-literal flows.
	IPs *IPSet
	// Bogons adds the compiled-in private/loopback/link-local table to IPs.
	// Defaults to true: dpb must never desync a flow to 192.168.0.1.
	Bogons *bool
	// IncludeOnly implements `--include`: when set, a host with no ScopeWatch
	// rule match is relayed directly and never escalated.
	IncludeOnly bool
	// Store is the durable verdict cache. Nil means no learning.
	Store Store
	// NetID namespaces store lookups. Nil means the zero NetworkID.
	NetID func() NetworkID
	// InspectPorts defaults to 443 and 80.
	InspectPorts []int
	// Ladder is the escalation ladder handed to a ScopeWatch verdict.
	Ladder []string
	// Suspended, when it returns true, forces ScopeDirect for everything. It is
	// the captive-portal suspend and the `dpb off` kill switch: both need the
	// tool to get out of the way without dropping live connections.
	Suspended func() bool
	// Recent supplies the connection history `dpb why` prints.
	Recent func(host string) []ConnSummary
	// Now defaults to time.Now.
	Now func() time.Time
}

// ruleset is swapped atomically so `dpb reload` can install new rules without
// locking out the connection path.
type ruleset struct {
	names *Matcher
	ips   *IPSet
}

// Engine is the shipped Scope. It is safe for concurrent use.
type Engine struct {
	rules atomic.Pointer[ruleset]

	includeOnly  bool
	store        Store
	netID        func() NetworkID
	inspectPorts []int
	ladder       []string
	suspended    func() bool
	recent       func(string) []ConnSummary
	now          func() time.Time
}

var _ Scope = (*Engine)(nil)

// NewEngine builds a Scope from rules, a store and a clock.
func NewEngine(o EngineOptions) *Engine {
	e := &Engine{
		includeOnly:  o.IncludeOnly,
		store:        o.Store,
		netID:        o.NetID,
		inspectPorts: append([]int(nil), o.InspectPorts...),
		ladder:       append([]string(nil), o.Ladder...),
		suspended:    o.Suspended,
		recent:       o.Recent,
		now:          o.Now,
	}
	if len(e.inspectPorts) == 0 {
		e.inspectPorts = append([]int(nil), defaultInspectPorts...)
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.netID == nil {
		e.netID = func() NetworkID { return NetworkID{} }
	}
	ips := o.IPs
	if o.Bogons == nil || *o.Bogons {
		ips = ips.WithBogons()
	}
	e.rules.Store(&ruleset{names: o.Rules, ips: ips})
	return e
}

// Reload swaps the rule set. Bogons are re-added on the same terms as at
// construction, so a reload can never quietly drop the private-address veto.
func (e *Engine) Reload(names *Matcher, ips *IPSet) {
	e.rules.Store(&ruleset{names: names, ips: ips.WithBogons()})
}

// InspectPorts reports the ports on which the first message is buffered.
func (e *Engine) InspectPorts() []int {
	return append([]int(nil), e.inspectPorts...)
}

func (e *Engine) inspected(port int) bool {
	for _, p := range e.inspectPorts {
		if p == port {
			return true
		}
	}
	return false
}

// ForName resolves the verdict for a named flow. The order is the one in the
// plan's data path A step 3: suspend, then IP literals, then rules, then the
// port filter, then the learned cache, then the ScopeWatch default.
func (e *Engine) ForName(host string, port int) Verdict {
	v, _ := e.forName(host, port)
	return v
}

func (e *Engine) forName(host string, port int) (Verdict, []Rule) {
	if e.suspended != nil && e.suspended() {
		return Verdict{
			Class:  ScopeDirect,
			Source: SrcDefault,
			Reason: "suspended: captive portal or kill switch active",
		}, nil
	}

	name := Normalize(host)
	if name == "" {
		// An unparseable name cannot be matched against any rule, so the only
		// honest answer is the safe default.
		return e.defaultVerdict(port, "hostname could not be normalised"), nil
	}

	// A host field very often holds an IP literal — SOCKS5 ATYP=IPv4, a
	// CONNECT to a bare address, a TUN flow with no name. Route it to the
	// address rules so the bogon table cannot be sidestepped by spelling.
	if addr, err := netip.ParseAddr(name); err == nil {
		v, rules := e.forAddr(canonAddr(addr), port)
		return v, rules
	}

	rs := e.rules.Load()
	matched := rs.names.Match(name)
	if len(matched) > 0 {
		if v, ok := e.ruleVerdict(matched[0], port); ok {
			return v, matched
		}
	}

	if !e.inspected(port) {
		return e.directPort(port), matched
	}
	if e.includeOnly && !hasClass(matched, ScopeWatch) {
		return Verdict{
			Class:  ScopeDirect,
			Source: SrcDefault,
			Reason: "--include is set and this host is not listed",
		}, matched
	}
	if v, ok := e.cached(name); ok {
		return v, matched
	}
	return e.defaultVerdict(port, ""), matched
}

// ForAddr resolves the verdict for a flow with no name: a TUN packet whose
// destination the ReverseMap could not name, or a SOCKS5 request carrying a
// raw address.
func (e *Engine) ForAddr(ap netip.AddrPort) Verdict {
	if e.suspended != nil && e.suspended() {
		return Verdict{
			Class:  ScopeDirect,
			Source: SrcDefault,
			Reason: "suspended: captive portal or kill switch active",
		}
	}
	v, _ := e.forAddr(canonAddr(ap.Addr()), int(ap.Port()))
	return v
}

func (e *Engine) forAddr(addr netip.Addr, port int) (Verdict, []Rule) {
	if !addr.IsValid() {
		return e.defaultVerdict(port, "invalid address"), nil
	}
	rs := e.rules.Load()
	matched := rs.ips.Match(addr)
	if len(matched) > 0 {
		if v, ok := e.ruleVerdict(matched[0], port); ok {
			return v, matched
		}
	}
	if !e.inspected(port) {
		return e.directPort(port), matched
	}
	if e.includeOnly && !hasClass(matched, ScopeWatch) {
		return Verdict{
			Class:  ScopeDirect,
			Source: SrcDefault,
			Reason: "--include is set and this address is not listed",
		}, matched
	}
	// The store is keyed by host string, and an address literal is a perfectly
	// good key: a repeat visit to an unnamed destination still gets its cached
	// winner.
	if v, ok := e.cached(addr.String()); ok {
		return v, matched
	}
	// Deliberately ScopeWatch, not ScopeDirect. Under default-direct an unnamed
	// flow is judged by its own ClientHello and is exactly as safe as a named
	// one, which is why this plan has no fake-IP layer.
	return e.defaultVerdict(port, "no name for this address"), matched
}

// ruleVerdict turns a matched rule into a verdict. It returns ok=false for a
// rule whose class does not decide on its own (an --include rule), so the
// caller falls through to the port filter and the cache.
func (e *Engine) ruleVerdict(r Rule, port int) (Verdict, bool) {
	switch r.Class {
	case ScopeBypass:
		return Verdict{
			Class:    ScopeBypass,
			Source:   r.source(),
			Reason:   "matched bypass rule " + r.Pattern,
			RuleText: r.Pattern,
			RuleFrom: r.Where(),
		}, true
	case ScopeDirect:
		return Verdict{
			Class:    ScopeDirect,
			Source:   r.source(),
			Reason:   "matched direct rule " + r.Pattern,
			RuleText: r.Pattern,
			RuleFrom: r.Where(),
		}, true
	case ScopeDesync:
		if !e.inspected(port) {
			return Verdict{}, false
		}
		return Verdict{
			Class:    ScopeDesync,
			Spec:     "",
			Ladder:   append([]string(nil), e.ladder...),
			Source:   SrcUserInclude,
			Reason:   "matched forced-desync rule " + r.Pattern,
			RuleText: r.Pattern,
			RuleFrom: r.Where(),
		}, true
	default:
		return Verdict{}, false
	}
}

func (e *Engine) cached(key string) (Verdict, bool) {
	if e.store == nil {
		return Verdict{}, false
	}
	v, ok := e.store.Get(e.netID(), key)
	if !ok {
		return Verdict{}, false
	}
	switch v.Source {
	case SrcLearnedPlain:
		// A host that has been observed to work plain is relayed with no
		// buffering at all. That is the whole payoff of caching both outcomes:
		// a bank costs nothing after its first visit.
		v.Class = ScopeDirect
		if v.Reason == "" {
			v.Reason = "cached: plain worked on this network"
		}
	case SrcLearnedDesync, SrcProbed:
		v.Class = ScopeDesync
		if len(v.Ladder) == 0 {
			v.Ladder = append([]string(nil), e.ladder...)
		}
		if v.Reason == "" {
			v.Reason = "cached: " + v.Spec + " worked on this network"
		}
	default:
		return Verdict{}, false
	}
	return v, true
}

func (e *Engine) directPort(port int) Verdict {
	return Verdict{
		Class:  ScopeDirect,
		Source: SrcDefault,
		Reason: fmt.Sprintf("port %d is not inspected", port),
	}
}

func (e *Engine) defaultVerdict(port int, why string) Verdict {
	if !e.inspected(port) {
		return e.directPort(port)
	}
	reason := "default: send the first message unmodified and escalate only on reset"
	if why != "" {
		reason = why + "; " + reason
	}
	return Verdict{
		Class:  ScopeWatch,
		Ladder: append([]string(nil), e.ladder...),
		Source: SrcDefault,
		Reason: reason,
	}
}

func hasClass(rules []Rule, c ScopeClass) bool {
	for _, r := range rules {
		if r.Class == c {
			return true
		}
	}
	return false
}

// Explain assembles the full decision chain for `dpb why`.
func (e *Engine) Explain(host string) Explanation {
	port := e.inspectPorts[0]
	v, matched := e.forName(host, port)
	x := Explanation{
		Input:     strings.TrimSpace(host),
		Punycode:  Normalize(host),
		Matched:   matched,
		Effective: v,
	}
	if e.recent != nil {
		x.Recent = e.recent(x.Punycode)
	}
	return x
}
