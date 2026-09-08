// Package buildinfo carries the identity of this binary.
//
// The values are set at link time by the release pipeline. They are plain vars
// rather than consts because -X can only patch vars, and they are read through
// accessors so that a build without ldflags still reports something honest
// (the VCS stamp Go embeds automatically) instead of a bare "dev".
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Set with -ldflags "-X github.com/mumudevx/dpb/internal/buildinfo.Version=..."
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

const (
	// Name is the binary name, used in the user agent and in log prefixes.
	Name = "dpb"

	unknown = "unknown"
	devVer  = "dev"
)

type stamp struct {
	version string
	commit  string
	date    string
	dirty   bool
}

var (
	once     sync.Once
	resolved stamp
)

func load() stamp {
	once.Do(func() { resolved = resolveStamp(Version, Commit, Date, debug.ReadBuildInfo) })
	return resolved
}

// resolveStamp is pure so the fallback paths a `go test` binary cannot reach
// on its own (no ldflags, no VCS stamp, a dirty tree) are still unit-tested.

func resolveStamp(version, commit, date string, read func() (*debug.BuildInfo, bool)) stamp {
	s := stamp{version: version, commit: commit, date: date}

	bi, ok := read()
	if ok {
		for _, kv := range bi.Settings {
			switch kv.Key {
			case "vcs.revision":
				if s.commit == "" {
					s.commit = kv.Value
				}
			case "vcs.time":
				if s.date == "" {
					s.date = kv.Value
				}
			case "vcs.modified":
				s.dirty = kv.Value == "true"
			}
		}
		// A `go install module@version` build has a real module version even
		// with no ldflags; prefer it over the "dev" placeholder.
		if s.version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			s.version = bi.Main.Version
		}
	}

	if s.version == "" {
		s.version = devVer
	}
	if s.commit == "" {
		s.commit = unknown
	}
	if s.date == "" {
		s.date = unknown
	}
	return s
}

// V returns the version string, e.g. "0.1.0" or "dev".
func V() string { return load().version }

// C returns the full commit hash, or "unknown".
func C() string { return load().commit }

// D returns the build date, or "unknown".
func D() string { return load().date }

// Dirty reports whether the working tree had uncommitted changes at build time.
// A dirty binary must not be trusted to match any published checksum.
func Dirty() bool { return load().dirty }

// Platform is the GOOS/GOARCH this binary was compiled for.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// Short is the one-line identity used by `dpb version` and the startup banner.
func Short() string {
	s := load()
	b := strings.Builder{}
	b.WriteString(Name)
	b.WriteString(" ")
	b.WriteString(s.version)
	if c := shortCommit(s.commit); c != "" {
		b.WriteString(" (")
		b.WriteString(c)
		if s.dirty {
			b.WriteString("-dirty")
		}
		b.WriteString(")")
	}
	b.WriteString(" ")
	b.WriteString(Platform())
	return b.String()
}

func shortCommit(c string) string {
	if c == "" || c == unknown {
		return ""
	}
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// UserAgent is the HTTP User-Agent for the tool's OWN outbound requests — DoH
// queries and the captive-portal canary — never for proxied client traffic,
// which is relayed byte-for-byte.
//
// It deliberately does not include the commit or the platform: a DoH resolver
// on a censored line is a party we do not have to trust, and a
// per-build-unique string would make individual users distinguishable.
func UserAgent() string { return Name + "/" + V() }
