// Package config defines region profiles and the precedence-based resolution
// of built-in defaults, an optional user config file, and explicit CLI flags.
package config

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
)

//go:embed embed/*.toml
var builtinFS embed.FS

// Duration is a TOML-friendly time.Duration (parsed from strings like "5m").
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

// ResolverSpec is one upstream DNS resolver in the fallback chain.
type ResolverSpec struct {
	Type string `toml:"type"` // "doh" | "dot" | "udp"
	URL  string `toml:"url"`
	Name string `toml:"name"`
}

// DNSConfig is the ordered resolver chain plus cache TTL.
type DNSConfig struct {
	Resolvers []ResolverSpec `toml:"resolvers"`
	CacheTTL  Duration       `toml:"cache_ttl"`
}

// StrategyChain selects the desync transformers + single emitter and their
// parameters.
type StrategyChain struct {
	Transformers []string `toml:"transformers"`
	Emitter      string   `toml:"emitter"`
	SplitOffset  int      `toml:"split_offset"`
	SplitSizes   []int    `toml:"split_sizes"`
	FragWindow   int      `toml:"frag_window"`
	FakeTTL      int      `toml:"fake_ttl"`
}

// Filter scopes which connections the desync engine is applied to.
type Filter struct {
	Ports    []int    `toml:"ports"`
	SNIMatch []string `toml:"sni_match"`
	SNISkip  []string `toml:"sni_skip"`
}

// Profile is a complete region configuration.
type Profile struct {
	Name        string        `toml:"name"`
	Description string        `toml:"description"`
	DNS         DNSConfig     `toml:"dns"`
	Strategy    StrategyChain `toml:"strategy"`
	Filter      Filter        `toml:"filter"`
}

// ToSpec converts the strategy chain into the dependency-free desync.Spec.
func (p Profile) ToSpec() desync.Spec {
	return desync.Spec{
		Transformers: p.Strategy.Transformers,
		Emitter:      p.Strategy.Emitter,
		SplitOffset:  p.Strategy.SplitOffset,
		SplitSizes:   p.Strategy.SplitSizes,
		FragWindow:   p.Strategy.FragWindow,
		FakeTTL:      p.Strategy.FakeTTL,
	}
}

// Validate enforces the composition rule and known strategy names.
func (p Profile) Validate() error {
	if p.Strategy.Emitter != "" && !contains(desync.KnownEmitters(), p.Strategy.Emitter) {
		return fmt.Errorf("profile %q: unknown emitter %q (known: %s)",
			p.Name, p.Strategy.Emitter, strings.Join(desync.KnownEmitters(), ", "))
	}
	for _, t := range p.Strategy.Transformers {
		if !contains(desync.KnownTransformers(), t) {
			return fmt.Errorf("profile %q: unknown transformer %q (known: %s)",
				p.Name, t, strings.Join(desync.KnownTransformers(), ", "))
		}
	}
	if len(p.DNS.Resolvers) == 0 {
		return fmt.Errorf("profile %q: no DNS resolvers configured", p.Name)
	}
	return nil
}

// BuiltinNames lists embedded profile names, sorted.
func BuiltinNames() []string {
	entries, _ := fs.ReadDir(builtinFS, "embed")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".toml"))
	}
	sort.Strings(names)
	return names
}

// LoadBuiltin decodes an embedded profile by name.
func LoadBuiltin(name string) (Profile, error) {
	var p Profile
	data, err := builtinFS.ReadFile("embed/" + name + ".toml")
	if err != nil {
		return p, fmt.Errorf("no built-in profile %q (available: %s)",
			name, strings.Join(BuiltinNames(), ", "))
	}
	if err := toml.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("decode built-in profile %q: %w", name, err)
	}
	if p.Name == "" {
		p.Name = name
	}
	return p, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
