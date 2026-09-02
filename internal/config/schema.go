package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
)

// The schema decodes with UNKNOWN-KEY REJECTION, and that is the point of the
// file rather than a nicety.
//
// MEASUREMENTS.md §3.5 records the previous implementation shipping a
// `sni_match` setting that was declared in the config, documented, recommended
// to users — and read nowhere. A user who set it believed they had changed the
// tool's behaviour and had not. Two mechanical defences here make that shape
// impossible: toml.MetaData.Undecoded() turns a key this build does not know
// into a load error naming the key and the file, and
// TestEverySchemaKeyIsReadOrDeclaredDeferred fails the build on a key this
// build decodes and then never reads.

// Duration is a time.Duration that decodes from a TOML string such as "250ms".
//
// TOML has no duration type and BurntSushi's decoder will happily put an
// integer into a time.Duration field, where 5 would mean five nanoseconds. A
// string with an explicit unit is the only spelling that cannot be misread.
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("not a duration (want a string with a unit, e.g. \"250ms\"): %s", b)
	}
	if v < 0 {
		return fmt.Errorf("duration must not be negative: %s", b)
	}
	*d = Duration(v)
	return nil
}

// MarshalText implements encoding.TextMarshaler so a written-back config
// round-trips.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.D().String()), nil }

// D is the duration as time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Mode is the escalation policy for an in-scope host.
type Mode string

const (
	// ModeWatch is the shipped default and the reason this tool is shaped the
	// way it is: connect with no desync, escalate only on a reset before any
	// server byte reaches the client. MEASUREMENTS.md §5.2 calls it a
	// correctness requirement, not an optimisation.
	ModeWatch Mode = "watch"
	// ModeAlways applies the configured strategy on attempt one. It is what a
	// user reaches for when they know their line and accept that the ten
	// measured regressors of §5.1 are still bypassed by the compiled-in list.
	ModeAlways Mode = "always"
	// ModeNever desyncs nothing. It is `dpb off` written into a file: the
	// listeners still run and still relay, so the proxy settings stay valid.
	ModeNever Mode = "never"
)

var modes = []Mode{ModeWatch, ModeAlways, ModeNever}

// UnmarshalText implements encoding.TextUnmarshaler.
func (m *Mode) UnmarshalText(b []byte) error {
	return unmarshalEnum((*string)(m), string(b), modeStrings(), "mode")
}

func modeStrings() []string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, string(m))
	}
	return out
}

// ProxyStyle selects which system proxy mechanisms are set.
type ProxyStyle string

const (
	// StylePAC sets only the auto-proxy URL. macOS treats an unfetchable PAC
	// URL as DIRECT, so process death fails OPEN.
	StylePAC ProxyStyle = "pac"
	// StyleExplicit sets the web and secure proxies. It fails CLOSED into a
	// total outage if dpb dies, which is why it is not the default.
	StyleExplicit ProxyStyle = "explicit"
	// StyleEnv sets HTTP_PROXY/HTTPS_PROXY/NO_PROXY through launchctl. GT24:
	// Discord's updater.node is an in-process reqwest addon whose only proxy
	// source is the environment.
	StyleEnv ProxyStyle = "env"
	// StyleBoth is pac + env, the shipped default: PAC covers CFNetwork and
	// Chromium/Electron, the environment covers reqwest/curl/Go/Python/Node.
	StyleBoth ProxyStyle = "both"
	// StyleNone mutates nothing. It is what the offline acceptance runs under
	// and what a user who configures their browser by hand wants.
	StyleNone ProxyStyle = "none"
)

var proxyStyles = []ProxyStyle{StylePAC, StyleExplicit, StyleEnv, StyleBoth, StyleNone}

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *ProxyStyle) UnmarshalText(b []byte) error {
	return unmarshalEnum((*string)(p), string(b), styleStrings(), "proxy_style")
}

func styleStrings() []string {
	out := make([]string, 0, len(proxyStyles))
	for _, s := range proxyStyles {
		out = append(out, string(s))
	}
	return out
}

func validStyle(p ProxyStyle) bool {
	for _, s := range proxyStyles {
		if s == p {
			return true
		}
	}
	return false
}

// SetsPAC reports whether this style points the system at our PAC URL.
func (p ProxyStyle) SetsPAC() bool { return p == StylePAC || p == StyleBoth }

// SetsExplicit reports whether this style sets the web/secure proxy.
func (p ProxyStyle) SetsExplicit() bool { return p == StyleExplicit }

// SetsEnv reports whether this style exports the proxy environment.
func (p ProxyStyle) SetsEnv() bool { return p == StyleEnv || p == StyleBoth }

// Config is the resolved configuration. Every field is read by this build or
// listed in deferredKeys with the milestone that reads it.
type Config struct {
	// Profile records which embedded profile the layering started from. It is
	// informational: setting it in a file does not change which profile loads,
	// because the profile has already been chosen by the time a file is read.
	Profile string `toml:"profile"`

	Mode Mode `toml:"mode"`

	Listen     string     `toml:"listen"`
	Port       int        `toml:"port"`
	SOCKSPort  int        `toml:"socks_port"`
	ProxyStyle ProxyStyle `toml:"proxy_style"`
	SetDNS     bool       `toml:"set_dns"`
	DNSPort    int        `toml:"dns_port"`

	Strategy      string   `toml:"strategy"`
	Ladder        string   `toml:"ladder"`
	MaxAttempts   int      `toml:"max_attempts"`
	AttemptBudget Duration `toml:"attempt_budget"`
	MaxSegments   int      `toml:"max_segments"`
	InspectPorts  []int    `toml:"inspect_ports"`

	FirstByteWait Duration `toml:"first_byte_wait"`
	CompleteWait  Duration `toml:"complete_wait"`
	MaxAssembly   Duration `toml:"max_assembly"`
	FirstMsgMax   int      `toml:"first_msg_max"`
	IdleTimeout   Duration `toml:"idle_timeout"`

	SmallWriteRate  int `toml:"small_write_rate"`
	SmallWriteBurst int `toml:"small_write_burst"`

	Learn           bool `toml:"learn"`
	VerdictCacheCap int  `toml:"verdict_cache_cap"`

	// Bypass adds to the compiled-in list in excludes.go. There is no key that
	// removes from it.
	Bypass []string `toml:"bypass"`
	// Include, when non-empty, is the ONLY set of names that may be escalated.
	Include []string `toml:"include"`

	DNS    DNS    `toml:"dns"`
	Prober Prober `toml:"prober"`

	// bypassFrom and includeFrom record which document last set the list, so a
	// rule compiled out of it can name the file a user has to edit. They are
	// not keys: a layered merge has no per-entry provenance to report, and
	// claiming a line number we do not have would be worse than naming none.
	bypassFrom  string
	includeFrom string
}

// DNS configures the resolver chain.
type DNS struct {
	// Chain is "default" (resolve.DefaultEndpoints, the measured chain) or
	// "custom", which requires at least one [[dns.endpoint]].
	Chain string `toml:"chain"`
	// Endpoints are the custom chain, ignored when Chain is "default".
	Endpoints []Endpoint `toml:"endpoint"`
	// PrependDoH and PrependUDP put an operator's own resolver in front of the
	// chain without restating it. They are `--dns-doh` and `--dns-udp`.
	PrependDoH []string `toml:"prepend_doh"`
	PrependUDP []string `toml:"prepend_udp"`
	// AllowTCP53 exists only so that setting it fails at parse time with the
	// measurement in the error text. See Validate.
	AllowTCP53 bool `toml:"allow_tcp53"`
	// AAAA is "auto", "allow" or "suppress".
	AAAA   string   `toml:"aaaa"`
	PerTry Duration `toml:"per_try"`
}

// Endpoint is one custom resolver rung.
type Endpoint struct {
	Label     string   `toml:"label"`
	Transport string   `toml:"transport"`
	Target    string   `toml:"target"`
	Bootstrap []string `toml:"bootstrap"`
}

// Prober is the seed data `dpb tune` measures against. Nothing in M11 reads it;
// it lives here because the seeds are profile data, not command-line data, and
// deferredKeys records that.
type Prober struct {
	Blocked     []string `toml:"blocked"`
	Control     string   `toml:"control"`
	ControlAddr string   `toml:"control_addr"`
	// Fragile defaults to FragileHosts() when empty, so the compatibility axis
	// and the compiled-in bypass list can never disagree.
	Fragile     []string `toml:"fragile"`
	Reps        int      `toml:"reps"`
	Cooldown    Duration `toml:"cooldown"`
	Concurrency int      `toml:"concurrency"`
}

// deferredKeys names the schema keys this build decodes but does not act on,
// with the milestone that will. A key that is neither read nor listed here
// fails TestEverySchemaKeyIsReadOrDeclaredDeferred.
var deferredKeys = map[string]string{
	"Blocked":     "M13 (dpb tune): blocked seed targets",
	"Control":     "M13 (dpb tune): benign-SNI control name",
	"ControlAddr": "M13 (dpb tune): the address the control is pinned to",
	"Fragile":     "M13 (dpb tune): the compatibility axis",
	"Reps":        "M13 (dpb tune): reps per candidate",
	"Cooldown":    "M13 (dpb tune): inter-rep cooldown",
	"Concurrency": "M13 (dpb tune): parallel trials",
}

// Defaults is the base every layer is applied on top of. It matches
// embed/global.toml, which is decoded over it, so a key missing from the
// embedded file still has a defined value.
func Defaults() *Config {
	return &Config{
		Profile:         "global",
		Mode:            ModeWatch,
		Listen:          "127.0.0.1",
		Port:            8080,
		SOCKSPort:       1080,
		ProxyStyle:      StyleBoth,
		SetDNS:          false,
		DNSPort:         5353,
		Ladder:          "tr",
		MaxAttempts:     5,
		AttemptBudget:   Duration(5 * time.Second),
		MaxSegments:     16,
		InspectPorts:    []int{443, 80},
		FirstByteWait:   Duration(250 * time.Millisecond),
		CompleteWait:    Duration(250 * time.Millisecond),
		MaxAssembly:     Duration(2 * time.Second),
		FirstMsgMax:     64 << 10,
		IdleTimeout:     Duration(120 * time.Second),
		SmallWriteRate:  512,
		SmallWriteBurst: 64,
		Learn:           true,
		VerdictCacheCap: 4096,
		DNS: DNS{
			Chain:  "default",
			AAAA:   "auto",
			PerTry: Duration(4 * time.Second),
		},
		Prober: Prober{
			Reps:        3,
			Cooldown:    Duration(400 * time.Millisecond),
			Concurrency: 4,
		},
	}
}

func more(keys []string) string {
	if len(keys) == 1 {
		return ""
	}
	return fmt.Sprintf(" (and %d more: %s)", len(keys)-1, strings.Join(keys[1:], ", "))
}

// Validate checks the values that are wrong on their own, before anything they
// would configure is built.
func (c *Config) Validate() error {
	if c.DNS.AllowTCP53 {
		// There is no lever to turn this on: resolve exposes no way to build a
		// plaintext TCP DNS client at all, and a gate test fails the build on
		// one. Saying so with the measurement attached is the whole value of
		// the key existing.
		return fmt.Errorf("config: allow_tcp53: %w", resolve.ForbidTCP("tcp"))
	}
	if c.SetDNS {
		return fmt.Errorf("config: set_dns: the in-process resolver a proxy-mode " +
			"`--set-dns on` would point the system at is not built yet (M15); " +
			"proxy mode does not need it, because a proxied client hands us the " +
			"name inside CONNECT")
	}
	switch c.Mode {
	case ModeWatch, ModeAlways, ModeNever:
	default:
		return fmt.Errorf("config: mode %q: want one of %s", c.Mode, strings.Join(modeStrings(), ", "))
	}
	// Validated here and not only in UnmarshalText, because a flag assigns the
	// field directly. An unrecognised style is not a harmless typo: SetsPAC,
	// SetsExplicit and SetsEnv would all answer false and dpb would start up
	// having quietly changed nothing, which reads exactly like success.
	if !validStyle(c.ProxyStyle) {
		return fmt.Errorf("config: proxy_style %q: want one of %s",
			c.ProxyStyle, strings.Join(styleStrings(), ", "))
	}
	if c.Mode == ModeAlways && c.Strategy == "" && c.Ladder == "" {
		return fmt.Errorf("config: mode = \"always\" needs a strategy or a ladder to apply")
	}
	if c.Port == 0 && c.SOCKSPort == 0 {
		return fmt.Errorf("config: port and socks_port are both 0, so nothing would listen")
	}
	if err := checkPort("port", c.Port); err != nil {
		return err
	}
	if err := checkPort("socks_port", c.SOCKSPort); err != nil {
		return err
	}
	if err := checkPort("dns_port", c.DNSPort); err != nil {
		return err
	}
	if c.Port != 0 && c.Port == c.SOCKSPort {
		return fmt.Errorf("config: port and socks_port are both %d", c.Port)
	}
	if c.Listen == "" {
		return fmt.Errorf("config: listen is empty; use 127.0.0.1 to stay on loopback")
	}
	if len(c.InspectPorts) == 0 {
		return fmt.Errorf("config: inspect_ports is empty, so no connection would ever be judged; " +
			"use mode = \"never\" to relay everything directly instead")
	}
	for _, p := range c.InspectPorts {
		if err := checkPort("inspect_ports", p); err != nil {
			return err
		}
		if p == 0 {
			return fmt.Errorf("config: inspect_ports contains 0")
		}
	}
	if c.MaxAttempts < 1 {
		return fmt.Errorf("config: max_attempts must be at least 1, got %d", c.MaxAttempts)
	}
	if c.MaxSegments < 1 {
		return fmt.Errorf("config: max_segments must be at least 1, got %d", c.MaxSegments)
	}
	if c.AttemptBudget <= 0 {
		return fmt.Errorf("config: attempt_budget must be positive")
	}
	if c.FirstMsgMax < 1024 {
		return fmt.Errorf("config: first_msg_max must be at least 1024 bytes, got %d", c.FirstMsgMax)
	}
	if c.SmallWriteRate < 0 || c.SmallWriteBurst < 0 {
		return fmt.Errorf("config: small_write_rate and small_write_burst must not be negative")
	}
	if c.VerdictCacheCap < 0 {
		return fmt.Errorf("config: verdict_cache_cap must not be negative")
	}
	switch c.DNS.AAAA {
	case "auto", "allow", "suppress":
	default:
		return fmt.Errorf("config: dns.aaaa %q: want one of auto, allow, suppress", c.DNS.AAAA)
	}
	switch c.DNS.Chain {
	case "default":
		if len(c.DNS.Endpoints) > 0 {
			return fmt.Errorf("config: dns.chain = \"default\" ignores [[dns.endpoint]]; " +
				"set dns.chain = \"custom\" to use them")
		}
	case "custom":
		if len(c.DNS.Endpoints) == 0 {
			return fmt.Errorf("config: dns.chain = \"custom\" needs at least one [[dns.endpoint]]")
		}
	default:
		return fmt.Errorf("config: dns.chain %q: want default or custom", c.DNS.Chain)
	}
	for i, e := range c.DNS.Endpoints {
		switch e.Transport {
		case "doh", "dot", "udp", "udp-alt":
		default:
			return fmt.Errorf("config: dns.endpoint[%d] %q: transport %q: want doh, dot, udp or udp-alt",
				i, e.Label, e.Transport)
		}
		if e.Target == "" {
			return fmt.Errorf("config: dns.endpoint[%d] %q: target is empty", i, e.Label)
		}
		for _, b := range e.Bootstrap {
			if _, err := netip.ParseAddr(strings.TrimSpace(b)); err != nil {
				return fmt.Errorf("config: dns.endpoint[%d] %q: bootstrap %q is not an IP address; "+
					"a name here would be resolved by the resolver we are trying to reach", i, e.Label, b)
			}
		}
		if e.Transport == "doh" && len(e.Bootstrap) == 0 {
			return fmt.Errorf("config: dns.endpoint[%d] %q: a doh endpoint needs bootstrap addresses, "+
				"or its URL's host would be resolved through the system resolver (MEASUREMENTS.md 5.4)", i, e.Label)
		}
	}
	return nil
}

func checkPort(key string, p int) error {
	if p < 0 || p > 65535 {
		return fmt.Errorf("config: %s %d is not a port number", key, p)
	}
	return nil
}

// AAAAMode maps the config's spelling onto resolve's.
func (c *Config) AAAAMode() resolve.AAAAMode {
	switch c.DNS.AAAA {
	case "allow":
		return resolve.AAAAAllow
	case "suppress":
		return resolve.AAAASuppress
	default:
		return resolve.AAAAAuto
	}
}

func unmarshalEnum(dst *string, in string, valid []string, key string) error {
	for _, v := range valid {
		if in == v {
			*dst = in
			return nil
		}
	}
	return fmt.Errorf("%s %q: want one of %s", key, in, strings.Join(valid, ", "))
}
