package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Overrides holds explicitly-set CLI flag values. A nil pointer means the flag
// was not set and the underlying profile value is kept.
type Overrides struct {
	Emitter     *string
	SplitOffset *int
	FragWindow  *int
	FakeTTL     *int
	DoHURL      *string
}

// userFile is an optional user config file. Each [profiles.NAME] table fully
// replaces the built-in profile of that name (copy a built-in and edit). Use
// CLI flags for granular per-run overrides.
type userFile struct {
	Profiles map[string]Profile `toml:"profiles"`
}

// DefaultConfigPath returns ~/.config/dpb/config.toml.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "dpb", "config.toml")
}

// Resolve builds the active profile: built-in defaults, then a same-named user
// profile from configPath (if the file exists and defines it), then CLI flag
// overrides, then validation.
func Resolve(name, configPath string, ov Overrides) (Profile, error) {
	p, builtinErr := LoadBuiltin(name)
	if builtinErr != nil {
		// Permit a user-only profile not shipped as a built-in.
		p = Profile{Name: name}
	}

	if configPath != "" {
		if up, ok, err := loadUserProfile(configPath, name); err != nil {
			return p, err
		} else if ok {
			if up.Name == "" {
				up.Name = name
			}
			p = up
		} else if builtinErr != nil {
			return p, builtinErr // neither built-in nor user-defined
		}
	} else if builtinErr != nil {
		return p, builtinErr
	}

	applyOverrides(&p, ov)
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func applyOverrides(p *Profile, ov Overrides) {
	if ov.Emitter != nil {
		p.Strategy.Emitter = *ov.Emitter
	}
	if ov.SplitOffset != nil {
		p.Strategy.SplitOffset = *ov.SplitOffset
	}
	if ov.FragWindow != nil {
		p.Strategy.FragWindow = *ov.FragWindow
	}
	if ov.FakeTTL != nil {
		p.Strategy.FakeTTL = *ov.FakeTTL
	}
	if ov.DoHURL != nil && *ov.DoHURL != "" {
		p.DNS.Resolvers = append([]ResolverSpec{
			{Type: "doh", URL: *ov.DoHURL, Name: "flag-doh"},
		}, p.DNS.Resolvers...)
	}
}

func loadUserProfile(path, name string) (Profile, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Profile{}, false, nil
		}
		return Profile{}, false, fmt.Errorf("read config %s: %w", path, err)
	}
	var uf userFile
	if err := toml.Unmarshal(data, &uf); err != nil {
		return Profile{}, false, fmt.Errorf("parse config %s: %w", path, err)
	}
	p, ok := uf.Profiles[name]
	return p, ok, nil
}
