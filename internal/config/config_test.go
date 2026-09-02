package config_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

func noEnv(string) string { return "" }

// netip.Addr holds unexported state, so cmp needs to be told how to compare
// one. Equality is what the type itself defines.
var addrEqual = cmp.Comparer(func(a, b netip.Addr) bool { return a == b })

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestTurkeyProfileLayersOverGlobal(t *testing.T) {
	t.Parallel()
	l, err := config.Load(config.Options{Profile: "turkey", Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Profile != "turkey" {
		t.Fatalf("profile = %q", l.Profile)
	}
	// Inherited from global.toml, which turkey.toml does not restate.
	if l.Port != 8080 || l.Mode != config.ModeWatch || l.ProxyStyle != config.StyleBoth {
		t.Fatalf("global layer did not survive: port=%d mode=%s style=%s", l.Port, l.Mode, l.ProxyStyle)
	}
	if got := l.ProberSeeds().Blocked; len(got) != 3 || got[0] != "discord.com" {
		t.Fatalf("prober seeds = %v", got)
	}
	if want := []string{"embedded global.toml", "embedded turkey.toml"}; !cmp.Equal(l.Sources, want) {
		t.Fatalf("sources = %v, want %v", l.Sources, want)
	}
}

// The M11 acceptance clause: "A config file with an unknown key is rejected with
// an error naming the key."
func TestUnknownKeyIsRejectedNamingTheKeyAndTheFile(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "sni_match = \"discord.com\"\n")
	_, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err == nil {
		t.Fatal("an unknown key loaded without error")
	}
	if !strings.Contains(err.Error(), "sni_match") {
		t.Fatalf("error does not name the key: %v", err)
	}
	if !strings.Contains(err.Error(), p) {
		t.Fatalf("error does not name the file: %v", err)
	}
	// The alternatives have to be in the message: "unknown key sni_match" alone
	// leaves the user with nothing to try.
	if !strings.Contains(err.Error(), "inspect_ports") {
		t.Fatalf("error lists no known keys: %v", err)
	}
}

func TestUnknownKeyInsideATableIsNamedWithItsTable(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "[dns]\nfallback_tcp = true\n")
	_, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err == nil || !strings.Contains(err.Error(), "dns.fallback_tcp") {
		t.Fatalf("err = %v, want it to name dns.fallback_tcp", err)
	}
}

func TestAllowTCP53FailsToLoadWithTheMeasurement(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "[dns]\nallow_tcp53 = true\n")
	_, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err == nil {
		t.Fatal("allow_tcp53 = true loaded")
	}
	if !strings.Contains(err.Error(), "allow_tcp53") {
		t.Fatalf("error does not name the key: %v", err)
	}
	// The value of the key existing at all is that its refusal carries the
	// reason. resolve.ForbidTCP's text is that reason.
	if !strings.Contains(err.Error(), resolve.ForbidTCP("tcp").Error()) {
		t.Fatalf("error carries no measurement: %v", err)
	}
}

func TestLaterLayersWin(t *testing.T) {
	t.Parallel()
	sys := write(t, "system.toml", "port = 9000\nlisten = \"127.0.0.2\"\n")
	usr := write(t, "user.toml", "port = 9100\n")
	extra := write(t, "extra.toml", "port = 9200\n")

	l, err := config.Load(config.Options{Profile: "global", System: sys, User: usr, Files: []string{extra}, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Port != 9200 {
		t.Fatalf("port = %d, want the --config layer to win", l.Port)
	}
	// The system layer's other key must survive a later layer that did not
	// mention it. That is the whole reason layering decodes over a value
	// instead of replacing it.
	if l.Listen != "127.0.0.2" {
		t.Fatalf("listen = %q, want the system layer to survive", l.Listen)
	}
}

func TestMissingFilesAreSkippedAndUnreadableOnesAreNot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := config.Load(config.Options{
		Profile: "global",
		System:  filepath.Join(dir, "absent.toml"),
		User:    filepath.Join(dir, "also-absent.toml"),
		Env:     noEnv,
	}); err != nil {
		t.Fatalf("a missing config file must not be an error: %v", err)
	}
	if _, err := config.Load(config.Options{Profile: "global", User: dir, Env: noEnv}); err == nil {
		t.Fatal("an unreadable config path loaded silently")
	}
}

func TestProfileKeyInTheUserFileSelectsTheProfile(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "profile = \"turkey\"\n")
	l, err := config.Load(config.Options{User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Profile != "turkey" {
		t.Fatalf("profile = %q, want the file's choice to select the embedded profile", l.Profile)
	}
}

func TestExplicitProfileBeatsTheFile(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "profile = \"turkey\"\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Profile != "global" {
		t.Fatalf("profile = %q", l.Profile)
	}
}

func TestUnknownProfileNamesTheAlternatives(t *testing.T) {
	t.Parallel()
	_, err := config.Load(config.Options{Profile: "turkiye", Env: noEnv})
	if err == nil || !strings.Contains(err.Error(), "turkey") {
		t.Fatalf("err = %v, want the valid profiles listed", err)
	}
}

func TestProfileMayBeAPath(t *testing.T) {
	t.Parallel()
	p := write(t, "mine.toml", "ladder = \"global\"\n")
	l, err := config.Load(config.Options{Profile: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Ladder != "global" {
		t.Fatalf("ladder = %q", l.Ladder)
	}
}

func TestEnvLayerIsDecodedLikeAFile(t *testing.T) {
	t.Parallel()
	env := map[string]string{"DPB_PORT": "9999", "DPB_MODE": "never", "DPB_LISTEN": ""}
	l, err := config.Load(config.Options{Profile: "global", Env: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Port != 9999 || l.Mode != config.ModeNever {
		t.Fatalf("env layer not applied: port=%d mode=%s", l.Port, l.Mode)
	}
	// An exported-but-empty variable is how a shell spells "unset". Taking it
	// literally would set listen = "" and fail validation for a variable nobody
	// meant to use.
	if l.Listen != "127.0.0.1" {
		t.Fatalf("listen = %q, want an empty DPB_LISTEN to be ignored", l.Listen)
	}
}

func TestEnvLayerIsValidatedNotTrusted(t *testing.T) {
	t.Parallel()
	env := map[string]string{"DPB_MODE": "aggressive"}
	_, err := config.Load(config.Options{Profile: "global", Env: func(k string) string { return env[k] }})
	if err == nil || !strings.Contains(err.Error(), "watch") {
		t.Fatalf("err = %v, want the valid modes listed", err)
	}
}

func TestFileLayerBeatsProfileAndEnvBeatsFile(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "port = 7000\n")
	env := map[string]string{"DPB_PORT": "7100"}
	l, err := config.Load(config.Options{
		Profile: "global", User: p,
		Env: func(k string) string { return env[k] },
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Port != 7100 {
		t.Fatalf("port = %d, want the environment layer to win over the file", l.Port)
	}
}

func TestDefaultProfileFollowsTheLocale(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"LANG": "tr_TR.UTF-8"}, "turkey"},
		{map[string]string{"LC_ALL": "tr_TR.UTF-8", "LANG": "en_US.UTF-8"}, "turkey"},
		{map[string]string{"LANG": "en_US.UTF-8"}, "global"},
		{map[string]string{}, "global"},
	} {
		got := config.DefaultProfile(func(k string) string { return tc.env[k] })
		if got != tc.want {
			t.Fatalf("DefaultProfile(%v) = %q, want %q", tc.env, got, tc.want)
		}
	}
}

// The shipped chain must be resolve.DefaultEndpoints() itself and not a copy of
// its addresses in TOML: a second copy is a second thing to keep in step with
// MEASUREMENTS.md §2.
func TestDefaultChainIsTheMeasuredOne(t *testing.T) {
	t.Parallel()
	l, err := config.Load(config.Options{Profile: "turkey", Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if diff := cmp.Diff(resolve.DefaultEndpoints(), l.Endpoints(), addrEqual); diff != "" {
		t.Fatalf("chain differs from resolve.DefaultEndpoints() (-want +got):\n%s", diff)
	}
}

func TestPrependedResolversComeFirst(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "[dns]\nprepend_udp = [\"192.0.2.1:53\"]\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eps := l.Endpoints()
	if len(eps) != len(resolve.DefaultEndpoints())+1 || eps[0].Target != "192.0.2.1:53" {
		t.Fatalf("prepended resolver is not first: %v", eps)
	}
}

func TestCustomChainNeedsBootstrapForDoH(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", `
[dns]
chain = "custom"
[[dns.endpoint]]
label = "mine"
transport = "doh"
target = "https://dns.example/dns-query"
`)
	_, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("err = %v, want a DoH endpoint without bootstrap addresses to be refused", err)
	}
}

func TestCustomChainRejectsANameAsBootstrap(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", `
[dns]
chain = "custom"
[[dns.endpoint]]
label = "mine"
transport = "doh"
target = "https://dns.example/dns-query"
bootstrap = ["dns.example"]
`)
	_, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err == nil || !strings.Contains(err.Error(), "not an IP address") {
		t.Fatalf("err = %v, want a hostname bootstrap refused", err)
	}
}

func TestCustomChainIsUsedInsteadOfTheDefault(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", `
[dns]
chain = "custom"
[[dns.endpoint]]
label = "quad9-alt"
transport = "udp-alt"
target = "9.9.9.9:9953"
`)
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eps := l.Endpoints()
	if len(eps) != 1 || eps[0].Label != "quad9-alt" {
		t.Fatalf("endpoints = %v, want only the custom one", eps)
	}
}

func TestDurationsNeedAUnit(t *testing.T) {
	t.Parallel()
	// A bare integer in a time.Duration field would mean nanoseconds, which is
	// how "attempt_budget = 5" becomes an instantly-expiring budget.
	p := write(t, "config.toml", "attempt_budget = 5\n")
	_, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err == nil || !strings.Contains(err.Error(), "duration") {
		t.Fatalf("err = %v, want a bare integer duration refused", err)
	}
}

func TestValidationRejects(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ body, want string }{
		"no listener":        {"port = 0\nsocks_port = 0\n", "nothing would listen"},
		"port collision":     {"port = 8080\nsocks_port = 8080\n", "both 8080"},
		"port out of range":  {"port = 70000\n", "not a port number"},
		"empty listen":       {"listen = \"\"\n", "listen is empty"},
		"no inspect ports":   {"inspect_ports = []\n", "no connection would ever be judged"},
		"zero attempts":      {"max_attempts = 0\n", "max_attempts"},
		"zero segments":      {"max_segments = 0\n", "max_segments"},
		"tiny first message": {"first_msg_max = 10\n", "first_msg_max"},
		"bad aaaa":           {"[dns]\naaaa = \"off\"\n", "dns.aaaa"},
		"bad proxy_style":    {"proxy_style = \"sock\"\n", "proxy_style"},
		"bad chain":          {"[dns]\nchain = \"doh\"\n", "dns.chain"},
		"set_dns":            {"set_dns = true\n", "M15"},
		"always with no strategy": {
			"mode = \"always\"\nstrategy = \"\"\nladder = \"\"\n", "needs a strategy",
		},
	} {
		p := write(t, "config.toml", tc.body)
		_, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
}

func TestModeAlwaysWithAStrategyLoads(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "mode = \"always\"\nstrategy = \"tlsfrag:pos=snimid\"\n")
	if _, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv}); err != nil {
		t.Fatalf("load: %v", err)
	}
}

func TestProxyStylePredicates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		style              config.ProxyStyle
		pac, explicit, env bool
	}{
		{config.StylePAC, true, false, false},
		{config.StyleExplicit, false, true, false},
		{config.StyleEnv, false, false, true},
		{config.StyleBoth, true, false, true},
		{config.StyleNone, false, false, false},
	} {
		if tc.style.SetsPAC() != tc.pac || tc.style.SetsExplicit() != tc.explicit || tc.style.SetsEnv() != tc.env {
			t.Errorf("%s: pac=%v explicit=%v env=%v", tc.style,
				tc.style.SetsPAC(), tc.style.SetsExplicit(), tc.style.SetsEnv())
		}
	}
}

func TestAAAAModeMapping(t *testing.T) {
	t.Parallel()
	for spelling, want := range map[string]resolve.AAAAMode{
		"auto":     resolve.AAAAAuto,
		"allow":    resolve.AAAAAllow,
		"suppress": resolve.AAAASuppress,
	} {
		c := config.Defaults()
		c.DNS.AAAA = spelling
		if got := c.AAAAMode(); got != want {
			t.Errorf("%s -> %v, want %v", spelling, got, want)
		}
	}
}

// The compiled-in list is extendable and not removable: no key takes anything
// out of it, and a config that sets bypass = [] still gets all of it.
func TestCompiledInBypassesCannotBeRemoved(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "bypass = []\n")
	l, err := config.Load(config.Options{Profile: "turkey", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rules, err := l.Rules()
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	m, err := policy.NewMatcher(rules)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	for _, host := range config.FragileHosts() {
		got := m.Match(host)
		if len(got) == 0 || got[0].Class != policy.ScopeBypass {
			t.Fatalf("%s is not bypassed after bypass = []: %v", host, got)
		}
		if got[0].From != policy.FromCompiledIn {
			t.Fatalf("%s: provenance = %q, want %q", host, got[0].From, policy.FromCompiledIn)
		}
	}
}

func TestFragileHostsAreTheTenMeasuredRegressors(t *testing.T) {
	t.Parallel()
	want := []string{
		"akbank.com", "isbank.com.tr", "yapikredi.com.tr", "ziraatbank.com.tr",
		"vakifbank.com.tr", "denizbank.com", "turkiye.gov.tr", "gib.gov.tr",
		"mhrs.gov.tr", "btk.gov.tr",
	}
	if diff := cmp.Diff(want, config.FragileHosts()); diff != "" {
		t.Fatalf("MEASUREMENTS.md 5.1's regressor list changed (-want +got):\n%s", diff)
	}
	for _, h := range want {
		if _, ok := config.MandatoryReason(h); !ok {
			t.Fatalf("%s carries no citation", h)
		}
	}
}

func TestEveryCompiledInEntryCitesItsSource(t *testing.T) {
	t.Parallel()
	for _, r := range config.Mandatory() {
		why, ok := config.MandatoryReason(r.Pattern)
		if !ok || strings.TrimSpace(why) == "" {
			t.Errorf("%s: no citation", r.Pattern)
		}
		if r.Line == 0 {
			t.Errorf("%s: no line, so `dpb why` cannot say where it came from", r.Pattern)
		}
	}
}

func TestBypassSplitsNamesFromAddresses(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "bypass = [\"example.org\", \"203.0.113.0/24\", \"198.51.100.7\"]\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	names, err := l.Rules()
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	ips, err := l.IPRules()
	if err != nil {
		t.Fatalf("ip rules: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("ip rules = %v, want the CIDR and the literal", ips)
	}
	for _, r := range names {
		if strings.Contains(r.Pattern, "/") {
			t.Fatalf("a CIDR reached the name matcher: %v", r)
		}
	}
	// Provenance: a user has to be able to find the file to edit.
	for _, r := range names {
		if r.Pattern == "example.org" && r.From != p {
			t.Fatalf("bypass rule provenance = %q, want %q", r.From, p)
		}
	}
}

func TestIncludeMakesTheScopeAnAllowList(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "include = [\"discord.com\"]\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !l.IncludeOnly() {
		t.Fatal("include did not turn on include-only")
	}
	rules, err := l.Rules()
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.Pattern == "discord.com" && r.Class == policy.ScopeWatch {
			found = true
		}
	}
	if !found {
		t.Fatalf("include did not produce a ScopeWatch rule: %v", rules)
	}
}

func TestBadPatternIsRejectedWhenCompiled(t *testing.T) {
	t.Parallel()
	p := write(t, "config.toml", "include = [\"*\"]\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := l.Rules(); err == nil {
		t.Fatal("a malformed pattern compiled")
	}
}

func TestLadderSpecsResolveThroughTheRegistry(t *testing.T) {
	t.Parallel()
	ops.Install()
	l, err := config.Load(config.Options{Profile: "turkey", Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	specs, err := l.LadderSpecs()
	if err != nil {
		t.Fatalf("ladder: %v", err)
	}
	want, _ := strategy.LadderSpecs("tr")
	if diff := cmp.Diff(want, specs); diff != "" {
		t.Fatalf("turkey profile ladder (-want +got):\n%s", diff)
	}
	if len(specs) == 0 || specs[0] != "" {
		t.Fatalf("rung 1 is %q, want plain", specs[0])
	}
}

func TestLadderMayBeAnExplicitSpecList(t *testing.T) {
	t.Parallel()
	ops.Install()
	p := write(t, "config.toml", "ladder = \"tlsfrag:pos=snimid,chunk:size=12\"\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	specs, err := l.LadderSpecs()
	if err != nil {
		t.Fatalf("ladder: %v", err)
	}
	if diff := cmp.Diff([]string{"tlsfrag:pos=snimid", "chunk:size=12"}, specs); diff != "" {
		t.Fatalf("(-want +got):\n%s", diff)
	}
}

func TestUnknownLadderIsAnError(t *testing.T) {
	t.Parallel()
	ops.Install()
	p := write(t, "config.toml", "ladder = \"tlsfrag:pos=nowhere\"\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := l.LadderSpecs(); err == nil {
		t.Fatal("an unparseable ladder resolved")
	}
}

// Validation gate 3: a profile naming a strategy the transport cannot satisfy
// REFUSES TO LOAD with the missing capability named. The previous
// implementation's flagship profile demanded root and then silently shipped the
// SNI unfragmented.
func TestCheckStrategiesRefusesAnUnsatisfiableLadder(t *testing.T) {
	t.Parallel()
	ops.Install()
	l, err := config.Load(config.Options{Profile: "turkey", Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	proxyCaps := strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL | strategy.CapOOB
	if err := l.CheckStrategies(proxyCaps); err != nil {
		t.Fatalf("the shipped TR ladder must load on a proxy-mode socket: %v", err)
	}
	// The same ladder on a transport with no urgent-data support must be
	// refused by name, because oob:pos=1 is one of its rungs.
	err = l.CheckStrategies(strategy.CapStreamWrite | strategy.CapNoDelay)
	if err == nil {
		t.Fatal("a ladder needing oob loaded on a transport without it")
	}
	if !strings.Contains(err.Error(), "oob") {
		t.Fatalf("error does not name the missing capability: %v", err)
	}
}

func TestCheckStrategiesChecksTheForcedStrategyToo(t *testing.T) {
	t.Parallel()
	ops.Install()
	p := write(t, "config.toml", "ladder = \"\"\nstrategy = \"oob:pos=1\"\n")
	l, err := config.Load(config.Options{Profile: "global", User: p, Env: noEnv})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := l.CheckStrategies(strategy.CapStreamWrite | strategy.CapNoDelay); err == nil {
		t.Fatal("a forced strategy the transport cannot emit loaded")
	}
}

func TestKnownKeysCoverEveryTable(t *testing.T) {
	t.Parallel()
	keys := config.KnownKeys()
	for _, want := range []string{"mode", "inspect_ports", "dns.chain", "dns.endpoint.label", "prober.reps"} {
		found := false
		for _, k := range keys {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Errorf("KnownKeys is missing %q: %v", want, keys)
		}
	}
}

func TestProfilesListsTheEmbeddedOnes(t *testing.T) {
	t.Parallel()
	if diff := cmp.Diff([]string{"global", "turkey"}, config.Profiles()); diff != "" {
		t.Fatalf("(-want +got):\n%s", diff)
	}
}

func TestEveryEmbeddedProfileLoads(t *testing.T) {
	t.Parallel()
	ops.Install()
	for _, p := range config.Profiles() {
		l, err := config.Load(config.Options{Profile: p, Env: noEnv})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, err := l.Rules(); err != nil {
			t.Fatalf("%s rules: %v", p, err)
		}
		if _, err := l.LadderSpecs(); err != nil {
			t.Fatalf("%s ladder: %v", p, err)
		}
	}
}

// A duration must survive a write-and-read cycle, or a config dpb wrote itself
// would fail to load.
func TestDurationRoundTrips(t *testing.T) {
	t.Parallel()
	d := config.Duration(250 * time.Millisecond)
	text, err := d.MarshalText()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back config.Duration
	if err := back.UnmarshalText(text); err != nil {
		t.Fatalf("unmarshal %q: %v", text, err)
	}
	if back != d {
		t.Fatalf("round trip = %v, want %v", back.D(), d.D())
	}
	if err := (&back).UnmarshalText([]byte("-1s")); err == nil {
		t.Fatal("a negative duration was accepted")
	}
}
