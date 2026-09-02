// Package config resolves dpb's configuration by layering documents, and
// refuses to load one it does not fully understand.
//
// The layers, in increasing precedence:
//
//	compiled-in defaults  → Defaults()
//	embedded global.toml  → the conservative base every profile starts from
//	embedded <profile>    → turkey.toml, or a path the operator named
//	/etc/dpb/config.toml  → machine policy
//	user config.toml      → the person's own settings
//	--config PATH         → an explicit file
//	DPB_* environment     → what a service manager can override without a file
//	flags                 → applied by the caller, which owns "was it typed?"
//
// A later layer only changes the keys it names, because the decoder writes into
// the value produced by the layer before it. That is also why unknown-key
// rejection has to be per document: the key is only wrong in the file it was
// written in.
package config

import (
	"embed"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

//go:embed embed/*.toml
var embedded embed.FS

// Profiles lists the embedded profile names.
func Profiles() []string {
	ents, err := embedded.ReadDir("embed")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, strings.TrimSuffix(e.Name(), ".toml"))
	}
	sort.Strings(out)
	return out
}

// Options drives Load. Every path is explicit so a test never reads the
// machine's real configuration.
type Options struct {
	// Profile names an embedded profile or a path to a .toml file. Empty means
	// "decide", in this order: DPB_PROFILE, a profile key in the user or system
	// file, then DefaultProfile.
	Profile string
	// System and User are the two standard files. An empty path is skipped and
	// a missing file is not an error; an unreadable one is.
	System string
	User   string
	// Files are extra documents applied last, in order. This is --config.
	Files []string
	// Env reads the environment layer. Nil means os.Getenv; a test passes its
	// own so the layer is exercised without touching the process environment.
	Env func(string) string
}

// DefaultSystemFile is where machine-wide policy lives.
const DefaultSystemFile = "/etc/dpb/config.toml"

// Loaded reports where the configuration came from, so `dpb run` can print it
// and a bug report can be read without guessing.
type Loaded struct {
	*Config
	// Sources lists every document that was actually applied, in order.
	Sources []string
}

// Load resolves the configuration.
func Load(o Options) (*Loaded, error) {
	getenv := o.Env
	if getenv == nil {
		getenv = os.Getenv
	}

	profile, err := chooseProfile(o, getenv)
	if err != nil {
		return nil, err
	}

	cfg := Defaults()
	l := &Loaded{Config: cfg}

	base, err := embedded.ReadFile("embed/global.toml")
	if err != nil {
		return nil, fmt.Errorf("config: read embedded global.toml: %w", err)
	}
	if err := cfg.apply(base, "embedded global.toml"); err != nil {
		return nil, err
	}
	l.Sources = append(l.Sources, "embedded global.toml")

	if profile != "global" {
		data, origin, err := readProfile(profile)
		if err != nil {
			return nil, err
		}
		if err := cfg.apply(data, origin); err != nil {
			return nil, err
		}
		l.Sources = append(l.Sources, origin)
	}

	for _, p := range append([]string{o.System, o.User}, o.Files...) {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("config: read %s: %w", p, err)
		}
		if err := cfg.apply(data, p); err != nil {
			return nil, err
		}
		l.Sources = append(l.Sources, p)
	}

	if frag, keys := envFragment(getenv); frag != "" {
		if err := cfg.apply([]byte(frag), "environment ("+strings.Join(keys, ", ")+")"); err != nil {
			return nil, err
		}
		l.Sources = append(l.Sources, "environment ("+strings.Join(keys, ", ")+")")
	}

	// The profile key is an input to chooseProfile, not an output: a later layer
	// that names a profile has already been consulted, and letting its literal
	// value stand would report a profile that was never loaded.
	cfg.Profile = profile

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return l, nil
}

// apply decodes one document over c and records where the list-valued keys came
// from, so a rule can name the file it was written in.
func (c *Config) apply(data []byte, origin string) error {
	md, err := toml.Decode(string(data), c)
	if err != nil {
		return fmt.Errorf("config: %s: %w", origin, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, 0, len(un))
		for _, k := range un {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return fmt.Errorf("config: %s: unknown key %s%s (this build knows: %s)",
			origin, keys[0], more(keys), strings.Join(KnownKeys(), ", "))
	}
	if md.IsDefined("bypass") {
		c.bypassFrom = origin
	}
	if md.IsDefined("include") {
		c.includeFrom = origin
	}
	return nil
}

func chooseProfile(o Options, getenv func(string) string) (string, error) {
	if o.Profile != "" {
		return o.Profile, nil
	}
	if v := strings.TrimSpace(getenv("DPB_PROFILE")); v != "" {
		return v, nil
	}
	for _, p := range []string{o.User, o.System} {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("config: read %s: %w", p, err)
		}
		if name := profileKey(data); name != "" {
			return name, nil
		}
	}
	return DefaultProfile(getenv), nil
}

// profileKey reads only the profile key. It tolerates every other key, because
// this runs before the document is validated: reporting "unknown key" twice,
// once from here and once from the real pass, would be noise.
func profileKey(data []byte) string {
	var probe struct {
		Profile string `toml:"profile"`
	}
	if _, err := toml.Decode(string(data), &probe); err != nil {
		return ""
	}
	return strings.TrimSpace(probe.Profile)
}

// DefaultProfile picks a profile from the environment's locale.
//
// The turkey profile is not merely a different ladder: it is the only one whose
// numbers were measured rather than reasoned about, so it is chosen only where
// those measurements apply. Everywhere else the global profile's structural
// ladder is the honest default.
func DefaultProfile(getenv func(string) string) string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.ToLower(getenv(k))
		if strings.HasPrefix(v, "tr_") || strings.Contains(v, "_tr.") || v == "tr" {
			return "turkey"
		}
	}
	return "global"
}

func readProfile(name string) (data []byte, origin string, err error) {
	if strings.ContainsRune(name, filepath.Separator) || strings.HasSuffix(name, ".toml") {
		b, err := os.ReadFile(name)
		if err != nil {
			return nil, "", fmt.Errorf("config: read profile %s: %w", name, err)
		}
		return b, name, nil
	}
	b, err := embedded.ReadFile("embed/" + name + ".toml")
	if err != nil {
		return nil, "", fmt.Errorf("config: unknown profile %q: want one of %s, or a path to a .toml file",
			name, strings.Join(Profiles(), ", "))
	}
	return b, "embedded " + name + ".toml", nil
}

// envKeys is the environment layer. It is a small explicit table rather than a
// generic DPB_<ANYTHING> mapping: the layer exists so a launchd plist can
// override the handful of settings a service manager owns, and a generic
// mapping would silently accept DPB_PROXYSTYLE and change nothing.
var envKeys = []struct {
	env   string
	key   string
	quote bool
}{
	{"DPB_LISTEN", "listen", true},
	{"DPB_PORT", "port", false},
	{"DPB_SOCKS_PORT", "socks_port", false},
	{"DPB_PROXY_STYLE", "proxy_style", true},
	{"DPB_MODE", "mode", true},
	{"DPB_LADDER", "ladder", true},
	{"DPB_STRATEGY", "strategy", true},
	{"DPB_LEARN", "learn", false},
}

// envFragment turns the environment layer into a TOML document, so it is
// decoded, range-checked and enum-checked by exactly the same code as a file.
func envFragment(getenv func(string) string) (string, []string) {
	var b strings.Builder
	var used []string
	for _, e := range envKeys {
		v, ok := lookupEnv(getenv, e.env)
		if !ok {
			continue
		}
		used = append(used, e.env)
		if e.quote {
			fmt.Fprintf(&b, "%s = %s\n", e.key, strconv.Quote(v))
		} else {
			fmt.Fprintf(&b, "%s = %s\n", e.key, v)
		}
	}
	return b.String(), used
}

// lookupEnv treats an empty value as unset. An exported-but-empty variable is
// how a shell spells "I did not set this", and taking it as listen = "" would
// fail validation for a variable nobody meant to use.
func lookupEnv(getenv func(string) string, k string) (string, bool) {
	v := strings.TrimSpace(getenv(k))
	return v, v != ""
}

// KnownKeys lists every key this build decodes, in sorted order. It is what the
// unknown-key error prints, because "unknown key foo" is only actionable
// alongside the alternatives.
func KnownKeys() []string {
	var out []string
	collectKeys(reflect.TypeOf(Config{}), "", &out)
	sort.Strings(out)
	return out
}

func collectKeys(t reflect.Type, prefix string, out *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		name := prefix + tag
		ft := f.Type
		if ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && !isTextUnmarshaler(f.Type) {
			collectKeys(ft, name+".", out)
			continue
		}
		*out = append(*out, name)
	}
}

func isTextUnmarshaler(t reflect.Type) bool {
	_, ok := reflect.New(t).Interface().(interface{ UnmarshalText([]byte) error })
	return ok
}

// Endpoints is the resolver chain as data.
//
// The default chain is resolve.DefaultEndpoints() rather than a copy of its
// addresses in TOML. A second copy of "1.1.1.1, 8.8.8.8, 9.9.9.9:853,
// 77.88.8.8:1253, 9.9.9.9:9953" is a second thing to keep in step with
// MEASUREMENTS.md §2, and the one in Go is pinned by a test.
func (c *Config) Endpoints() []resolve.Endpoint {
	var out []resolve.Endpoint
	for _, u := range c.DNS.PrependDoH {
		out = append(out, resolve.Endpoint{Label: "doh:" + u, Transport: "doh", Target: u})
	}
	for _, a := range c.DNS.PrependUDP {
		out = append(out, resolve.Endpoint{Label: "udp:" + a, Transport: "udp", Target: a})
	}
	if c.DNS.Chain == "custom" {
		for _, e := range c.DNS.Endpoints {
			out = append(out, resolve.Endpoint{
				Label:     e.Label,
				Transport: e.Transport,
				Target:    e.Target,
				Bootstrap: parseAddrs(e.Bootstrap),
			})
		}
		return out
	}
	return append(out, resolve.DefaultEndpoints()...)
}

// Rules compiles the name rules: the compiled-in list first, then the
// configured bypasses, then the include set.
//
// Order is provenance, not precedence — policy.Matcher resolves
// most-specific-first on its own — but it does decide which rule `dpb why`
// prints at the top for a host matched by two, and the compiled-in one is the
// one carrying a measurement.
func (c *Config) Rules() ([]policy.Rule, error) {
	rules := Mandatory()
	for _, h := range c.Bypass {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, err := policy.ParsePrefix(h); err == nil {
			continue // an address; IPRules takes it
		}
		rules = append(rules, policy.Rule{Pattern: h, Class: policy.ScopeBypass, From: c.origin(c.bypassFrom)})
	}
	for _, h := range c.Include {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		rules = append(rules, policy.Rule{Pattern: h, Class: policy.ScopeWatch, From: c.origin(c.includeFrom)})
	}
	if _, err := policy.NewMatcher(rules); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return rules, nil
}

// IPRules compiles the address entries of the bypass list. policy adds the
// bogon table itself, so nothing private, loopback or link-local is restated
// here.
func (c *Config) IPRules() ([]policy.Rule, error) {
	var rules []policy.Rule
	for _, h := range c.Bypass {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, err := policy.ParsePrefix(h); err != nil {
			continue
		}
		rules = append(rules, policy.Rule{Pattern: h, Class: policy.ScopeBypass, From: c.origin(c.bypassFrom)})
	}
	if _, err := policy.NewIPSet(rules); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return rules, nil
}

// IncludeOnly reports whether an include set was configured, which turns the
// scope engine into an allow-list.
func (c *Config) IncludeOnly() bool { return len(c.Include) > 0 }

func (c *Config) origin(s string) string {
	if s == "" {
		return "config"
	}
	return s
}

// LadderSpecs resolves the configured ladder against the strategy registry.
// The caller must have installed the op set first; a bare build parses only
// the plain rung.
func (c *Config) LadderSpecs() ([]string, error) {
	if c.Ladder == "" {
		return nil, nil
	}
	if specs, ok := strategy.LadderSpecs(c.Ladder); ok {
		return specs, nil
	}
	ss, err := strategy.ParseLadder(c.Ladder)
	if err != nil {
		return nil, fmt.Errorf("config: ladder %q: %w", c.Ladder, err)
	}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Spec)
	}
	return out, nil
}

// CheckStrategies is validation gate 3 from docs/PLAN.md: a profile naming a
// strategy the selected transport cannot satisfy REFUSES TO LOAD, with the
// missing capability named, instead of starting up and silently shipping the
// SNI unfragmented.
//
// It is checked against the transport's capabilities and not against a message,
// because whether a rung applies to a particular ClientHello is a per-connection
// question the ladder answers; whether the socket can ever emit it is a
// configuration question, and this is the place to answer it.
func (c *Config) CheckStrategies(caps strategy.Cap) error {
	specs, err := c.LadderSpecs()
	if err != nil {
		return err
	}
	if c.Strategy != "" {
		specs = append(specs, c.Strategy)
	}
	for _, spec := range specs {
		st, err := strategy.Parse(spec)
		if err != nil {
			return fmt.Errorf("config: strategy %q: %w", spec, err)
		}
		if missing := caps.Missing(st.Caps()); missing != 0 {
			return fmt.Errorf("config: strategy %q needs %s, which this transport does not have (it has %s)",
				specName(spec), missing, caps)
		}
	}
	return nil
}

func specName(s string) string {
	if s == "" {
		return "plain"
	}
	return s
}

// ProberSeeds returns the tune seeds with the defaults filled in. The fragile
// set falls back to FragileHosts() so the compatibility axis and the
// compiled-in bypass list are one list.
func (c *Config) ProberSeeds() Prober {
	p := c.Prober
	if len(p.Fragile) == 0 {
		p.Fragile = FragileHosts()
	}
	return p
}

// parseAddrs converts bootstrap literals. Validate has already rejected an
// unparseable one, so a bad entry here cannot silently shrink the list.
func parseAddrs(in []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			out = append(out, a)
		}
	}
	return out
}
