package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
)

func TestBuiltinProfilesValid(t *testing.T) {
	names := BuiltinNames()
	if len(names) == 0 {
		t.Fatal("no built-in profiles embedded")
	}
	for _, name := range names {
		p, err := LoadBuiltin(name)
		if err != nil {
			t.Fatalf("LoadBuiltin(%q): %v", name, err)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("profile %q invalid: %v", name, err)
		}
		// Each profile must build a working engine.
		if _, err := desync.New(p.ToSpec()); err != nil {
			t.Fatalf("profile %q engine: %v", name, err)
		}
	}
}

func TestTurkeyProfileShape(t *testing.T) {
	p, err := LoadBuiltin("turkey")
	if err != nil {
		t.Fatal(err)
	}
	if p.Strategy.Emitter != "split-at-sni" {
		t.Errorf("emitter = %q", p.Strategy.Emitter)
	}
	if len(p.Strategy.Transformers) != 1 || p.Strategy.Transformers[0] != "host-case" {
		t.Errorf("transformers = %v", p.Strategy.Transformers)
	}
	if p.DNS.CacheTTL.Std().Minutes() != 5 {
		t.Errorf("cache_ttl = %v", p.DNS.CacheTTL.Std())
	}
}

func TestResolveFlagOverride(t *testing.T) {
	emitter := "split-at-offset"
	off := 7
	p, err := Resolve("global", "", Overrides{Emitter: &emitter, SplitOffset: &off})
	if err != nil {
		t.Fatal(err)
	}
	if p.Strategy.Emitter != "split-at-offset" || p.Strategy.SplitOffset != 7 {
		t.Fatalf("override not applied: %+v", p.Strategy)
	}
}

func TestResolveUserFileReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[profiles.global]
name = "global"
[profiles.global.dns]
[[profiles.global.dns.resolvers]]
type = "doh"
url  = "https://example.test/dns-query"
name = "custom"
[profiles.global.strategy]
emitter = "multi-split"
split_sizes = [4, 8]
[profiles.global.filter]
ports = [443]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Resolve("global", path, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Strategy.Emitter != "multi-split" {
		t.Fatalf("user file not applied: %q", p.Strategy.Emitter)
	}
	if p.DNS.Resolvers[0].Name != "custom" {
		t.Fatalf("user dns not applied: %+v", p.DNS.Resolvers)
	}
}

func TestResolveUnknownProfile(t *testing.T) {
	if _, err := Resolve("nonexistent", "", Overrides{}); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}
