package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The compiled-in bypass list from the turkey profile, abbreviated to the
// entries whose behaviour differs. MEASUREMENTS.md §5.1 measured all ten
// regressors; these are the shapes.
func testRules(t *testing.T) *Matcher {
	t.Helper()
	m, err := NewMatcher([]Rule{
		{Pattern: "akbank.com", Class: ScopeBypass, From: FromCompiledIn},
		{Pattern: "isbank.com.tr", Class: ScopeBypass, From: FromCompiledIn},
		{Pattern: ".com.tr", Class: ScopeBypass, From: FromCompiledIn},
		{Pattern: ".gov.tr", Class: ScopeBypass, From: FromCompiledIn},
		{Pattern: "myintranet.example", Class: ScopeBypass, From: "~/.config/dpb/config.toml", Line: 31},
		{Pattern: "smtp.example", Class: ScopeDirect, From: "~/.config/dpb/config.toml", Line: 32},
		{Pattern: "discord.com", Class: ScopeWatch, From: "~/.config/dpb/config.toml", Line: 33},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

func newTestEngine(t *testing.T, mutate func(*EngineOptions)) (*Engine, *fakeClock) {
	t.Helper()
	clk := newClock()
	store, err := OpenStore("", clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	o := EngineOptions{
		Rules:  testRules(t),
		Store:  store,
		NetID:  netA,
		Ladder: []string{"", "tlsfrag:pos=snimid", "chunk:size=12"},
		Now:    clk.now,
	}
	if mutate != nil {
		mutate(&o)
	}
	return NewEngine(o), clk
}

func TestEngineDefaultsToWatchOnInspectPorts(t *testing.T) {
	e, _ := newTestEngine(t, nil)

	v := e.ForName("cloudflare.com", 443)
	if v.Class != ScopeWatch || v.Source != SrcDefault {
		t.Fatalf("ForName(cloudflare.com,443) = %+v, want a default watch", v)
	}
	if len(v.Ladder) != 3 || v.Ladder[1] != "tlsfrag:pos=snimid" {
		t.Errorf("ladder = %v, want the configured escalation ladder", v.Ladder)
	}
	if v.Reason == "" {
		t.Error("a verdict with no reason cannot be explained to a user")
	}
	// Port 80 carries the Host-header mutators and is inspected too.
	if got := e.ForName("cloudflare.com", 80).Class; got != ScopeWatch {
		t.Errorf("port 80 verdict = %v, want watch", got)
	}
	// Everything else is relayed with no first-message read at all — the
	// ordering that keeps SMTP, IMAP, POP3, FTP and MySQL from deadlocking.
	for _, port := range []int{25, 143, 3306, 22, 8443} {
		v := e.ForName("mail.example", port)
		if v.Class != ScopeDirect {
			t.Errorf("port %d verdict = %v, want direct", port, v.Class)
		}
		if !strings.Contains(v.Reason, "not inspected") {
			t.Errorf("port %d reason = %q", port, v.Reason)
		}
	}
	if got := e.InspectPorts(); len(got) != 2 || got[0] != 443 {
		t.Errorf("InspectPorts = %v", got)
	}
}

func TestEngineBypassRulesAreAnchoredAndAttributed(t *testing.T) {
	e, _ := newTestEngine(t, nil)

	v := e.ForName("www.isbank.com.tr", 443)
	if v.Class != ScopeBypass || v.Source != SrcBuiltinBypass {
		t.Fatalf("bank verdict = %+v, want a compiled-in bypass", v)
	}
	if v.RuleFrom != FromCompiledIn || v.RuleText != "isbank.com.tr" {
		t.Errorf("provenance = %q/%q", v.RuleText, v.RuleFrom)
	}
	if got := e.ForName("turkiye.gov.tr", 443).Class; got != ScopeBypass {
		t.Errorf(".gov.tr verdict = %v, want bypass", got)
	}

	// The defect this package exists to prevent.
	if got := e.ForName("evilakbank.com", 443).Class; got != ScopeWatch {
		t.Errorf("evilakbank.com = %v, want the default watch, not the bank's bypass", got)
	}
	if got := e.ForName("akbank.com.evil.tld", 443).Class; got != ScopeWatch {
		t.Errorf("akbank.com.evil.tld = %v, want the default watch", got)
	}
	if got := e.ForName("www.akbank.com", 443).Class; got != ScopeBypass {
		t.Errorf("www.akbank.com = %v, want the bank's bypass", got)
	}

	// A user rule carries its file and line, and is attributed as the user's.
	v = e.ForName("myintranet.example", 443)
	if v.Source != SrcUserBypass || v.RuleFrom != "~/.config/dpb/config.toml:31" {
		t.Errorf("user bypass = %+v", v)
	}
	v = e.ForName("smtp.example", 443)
	if v.Class != ScopeDirect || v.Source != SrcUserBypass {
		t.Errorf("user direct rule = %+v", v)
	}
	// A bypass holds on every port, inspected or not: it is a hard veto.
	if got := e.ForName("www.isbank.com.tr", 8443).Class; got != ScopeBypass {
		t.Errorf("bypass on an uninspected port = %v, want bypass", got)
	}
}

func TestEngineReadsTheLearnedCache(t *testing.T) {
	e, clk := newTestEngine(t, nil)
	store := e.store

	// MEASUREMENTS.md §5.2 step 4: a bank that worked plain is remembered, and
	// is thereafter relayed with no buffering at all.
	if err := store.Put(netA(), "cloudflare.com", Verdict{Source: SrcLearnedPlain}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v := e.ForName("cloudflare.com", 443)
	if v.Class != ScopeDirect || v.Source != SrcLearnedPlain {
		t.Fatalf("cached plain = %+v, want direct", v)
	}

	// A cached winner is applied on attempt one.
	exp := clk.now().Add(7 * 24 * time.Hour)
	if err := store.Put(netA(), "discord.gg", desyncVerdict("tlsfrag:pos=snimid", exp)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v = e.ForName("discord.gg", 443)
	if v.Class != ScopeDesync || v.Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("cached desync = %+v", v)
	}

	// After the 7-day TTL the host is unknown again, so a lifted block is
	// rediscovered rather than desynced forever.
	clk.advance(7*24*time.Hour + time.Second)
	if got := e.ForName("discord.gg", 443).Class; got != ScopeWatch {
		t.Errorf("expired verdict = %v, want the default watch", got)
	}

	// A cache entry never overrides a hard bypass.
	if err := store.Put(netA(), "isbank.com.tr", desyncVerdict("oob:pos=1", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := e.ForName("isbank.com.tr", 443).Class; got != ScopeBypass {
		t.Fatalf("a cached desync overrode a compiled-in bypass: %v", got)
	}

	// A verdict cached under a source that says nothing about how to connect
	// is ignored rather than guessed at.
	if err := store.Put(netA(), "odd.example", Verdict{Source: SrcDefault}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := e.ForName("odd.example", 443).Source; got != SrcDefault {
		t.Errorf("unusable cache entry = %v", got)
	}

	// A ladder is always supplied, even if the cached entry lost its own.
	if err := store.Put(netA(), "noladder.example", Verdict{Source: SrcProbed, Spec: "chunk:size=12"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if v := e.ForName("noladder.example", 443); v.Class != ScopeDesync || len(v.Ladder) != 3 {
		t.Errorf("probed verdict = %+v, want a desync with the default ladder", v)
	}
}

// A verdict learned on the home line must not be applied on a hotspot.
func TestEngineCacheIsNamespacedByNetwork(t *testing.T) {
	current := netA()
	e, _ := newTestEngine(t, func(o *EngineOptions) {
		o.NetID = func() NetworkID { return current }
	})
	if err := e.store.Put(netA(), "discord.com", desyncVerdict("tlsfrag:pos=snimid", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := e.ForName("discord.com", 443).Class; got != ScopeDesync {
		t.Fatalf("on network A = %v, want desync", got)
	}
	current = netB()
	if got := e.ForName("discord.com", 443).Class; got != ScopeWatch {
		t.Fatalf("on network B = %v, want the default watch", got)
	}
}

func TestEngineSuspendedRelaysEverythingDirectly(t *testing.T) {
	suspended := false
	e, _ := newTestEngine(t, func(o *EngineOptions) {
		o.Suspended = func() bool { return suspended }
	})
	if got := e.ForName("discord.com", 443).Class; got != ScopeWatch {
		t.Fatalf("baseline = %v", got)
	}
	suspended = true
	for _, v := range []Verdict{
		e.ForName("discord.com", 443),
		e.ForName("www.isbank.com.tr", 443),
		e.ForAddr(netip.MustParseAddrPort("1.2.3.4:443")),
	} {
		if v.Class != ScopeDirect {
			t.Errorf("suspended verdict = %+v, want direct", v)
		}
	}
}

func TestEngineIncludeOnly(t *testing.T) {
	e, _ := newTestEngine(t, func(o *EngineOptions) { o.IncludeOnly = true })

	// discord.com carries a ScopeWatch rule, so it stays in scope.
	if got := e.ForName("discord.com", 443).Class; got != ScopeWatch {
		t.Errorf("included host = %v, want watch", got)
	}
	if got := e.ForName("www.discord.com", 443).Class; got != ScopeWatch {
		t.Errorf("subdomain of an included host = %v, want watch", got)
	}
	// Everything else is relayed untouched, cache or no cache.
	v := e.ForName("cloudflare.com", 443)
	if v.Class != ScopeDirect || !strings.Contains(v.Reason, "--include") {
		t.Errorf("excluded host = %+v", v)
	}
	if err := e.store.Put(netA(), "cloudflare.com", desyncVerdict("chunk:size=12", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := e.ForName("cloudflare.com", 443).Class; got != ScopeDirect {
		t.Errorf("--include did not override a cached desync: %v", got)
	}
	v = e.ForAddr(netip.MustParseAddrPort("1.2.3.4:443"))
	if v.Class != ScopeDirect || !strings.Contains(v.Reason, "--include") {
		t.Errorf("excluded address = %+v", v)
	}
}

func TestEngineForAddr(t *testing.T) {
	ips, err := NewIPSet([]Rule{
		{Pattern: "203.0.113.0/24", Class: ScopeBypass, From: "cfg", Line: 9},
	})
	if err != nil {
		t.Fatalf("NewIPSet: %v", err)
	}
	e, _ := newTestEngine(t, func(o *EngineOptions) { o.IPs = ips })

	// An unnamed flow gets ScopeWatch and is judged by its own ClientHello.
	// That is exactly as safe as a named flow under default-direct, which is
	// why this design has no fake-IP layer.
	v := e.ForAddr(netip.MustParseAddrPort("162.159.128.233:443"))
	if v.Class != ScopeWatch || len(v.Ladder) == 0 {
		t.Fatalf("unnamed flow = %+v, want a watch with a ladder", v)
	}

	// The bogon table is compiled in and never has to be configured.
	for _, s := range []string{"192.168.0.1:443", "127.0.0.1:443", "[fe80::1]:443"} {
		if got := e.ForAddr(netip.MustParseAddrPort(s)).Class; got != ScopeBypass {
			t.Errorf("ForAddr(%s) = %v, want bypass", s, got)
		}
	}
	if got := e.ForAddr(netip.MustParseAddrPort("203.0.113.5:443")); got.Class != ScopeBypass ||
		got.RuleFrom != "cfg:9" {
		t.Errorf("configured address rule = %+v", got)
	}
	if got := e.ForAddr(netip.MustParseAddrPort("1.2.3.4:25")).Class; got != ScopeDirect {
		t.Errorf("uninspected port on an address = %v, want direct", got)
	}
	if got := e.ForAddr(netip.AddrPort{}).Class; got != ScopeDirect {
		t.Errorf("invalid AddrPort = %v, want a safe direct", got)
	}

	// An address arriving in the host field — SOCKS5 ATYP=IPv4, a CONNECT to a
	// bare address — must reach the same rules rather than being treated as a
	// name that matches nothing.
	if got := e.ForName("192.168.0.1", 443).Class; got != ScopeBypass {
		t.Errorf("ForName on a private literal = %v, want bypass", got)
	}
	if got := e.ForName("[::ffff:192.168.0.1]", 443).Class; got != ScopeBypass {
		t.Errorf("ForName on a bracketed 4-in-6 literal = %v, want bypass", got)
	}
	// An unusable hostname is still answered safely.
	v = e.ForName("not a host", 443)
	if v.Class != ScopeWatch || !strings.Contains(v.Reason, "normalis") {
		t.Errorf("unparseable host = %+v", v)
	}
	if got := e.ForName("not a host", 25).Class; got != ScopeDirect {
		t.Errorf("unparseable host on an uninspected port = %v", got)
	}
}

// Bogons are re-added on reload, so a rule file that forgets RFC1918 can never
// cause dpb to desync a flow to the user's own router.
func TestEngineReloadKeepsTheBogonVeto(t *testing.T) {
	e, _ := newTestEngine(t, nil)
	if got := e.ForName("discord.com", 443).Class; got != ScopeWatch {
		t.Fatalf("baseline = %v", got)
	}
	m, err := NewMatcher([]Rule{{Pattern: "discord.com", Class: ScopeBypass, From: "cfg", Line: 1}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	e.Reload(m, nil)
	if got := e.ForName("discord.com", 443).Class; got != ScopeBypass {
		t.Errorf("after reload = %v, want the new bypass", got)
	}
	if got := e.ForName("www.isbank.com.tr", 443).Class; got != ScopeWatch {
		t.Errorf("the replaced rule set still matched: %v", got)
	}
	if got := e.ForAddr(netip.MustParseAddrPort("10.1.2.3:443")).Class; got != ScopeBypass {
		t.Errorf("reload dropped the bogon veto: %v", got)
	}
}

func TestEngineDefaultsAndDegenerateOptions(t *testing.T) {
	e := NewEngine(EngineOptions{})
	if got := e.ForName("discord.com", 443).Class; got != ScopeWatch {
		t.Errorf("bare engine on 443 = %v, want watch", got)
	}
	if got := e.ForName("discord.com", 25).Class; got != ScopeDirect {
		t.Errorf("bare engine on 25 = %v, want direct", got)
	}
	if got := e.ForAddr(netip.MustParseAddrPort("10.0.0.1:443")).Class; got != ScopeBypass {
		t.Errorf("bare engine lost the bogon veto: %v", got)
	}
	x := e.Explain("discord.com")
	if x.Effective.Class != ScopeWatch || len(x.Matched) != 0 {
		t.Errorf("bare engine Explain = %+v", x)
	}

	// Bogons can be switched off deliberately, which the TUN loopback tests
	// need in order to reach a fake origin on 127.0.0.1.
	off := false
	e2 := NewEngine(EngineOptions{Bogons: &off, InspectPorts: []int{443}})
	if got := e2.ForAddr(netip.MustParseAddrPort("127.0.0.1:443")).Class; got != ScopeWatch {
		t.Errorf("Bogons=false still vetoed loopback: %v", got)
	}
}

// A rule that forces desync stands in for `dpb apply` and a tuned profile
// pinning a host, and must not fire on ports we do not inspect.
func TestEngineForcedDesyncRule(t *testing.T) {
	m, err := NewMatcher([]Rule{{Pattern: "discord.com", Class: ScopeDesync, From: "tuned.toml", Line: 4}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	e, _ := newTestEngine(t, func(o *EngineOptions) { o.Rules = m })
	v := e.ForName("discord.com", 443)
	if v.Class != ScopeDesync || v.Source != SrcUserInclude || len(v.Ladder) != 3 {
		t.Errorf("forced desync = %+v", v)
	}
	if got := e.ForName("discord.com", 25).Class; got != ScopeDirect {
		t.Errorf("forced desync leaked onto an uninspected port: %v", got)
	}
}

func TestEngineWithoutAStore(t *testing.T) {
	e, _ := newTestEngine(t, func(o *EngineOptions) { o.Store = nil })
	if got := e.ForName("discord.com", 443).Class; got != ScopeWatch {
		t.Errorf("storeless engine = %v, want watch", got)
	}
}

func TestEngineSatisfiesScope(t *testing.T) {
	var s Scope = NewEngine(EngineOptions{})
	if s.ForName("discord.com", 443).Class != ScopeWatch {
		t.Error("Scope.ForName")
	}
}
