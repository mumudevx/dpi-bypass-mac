package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func fakeBuildInfo(settings map[string]string, mainVersion string) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		bi := &debug.BuildInfo{}
		bi.Main.Version = mainVersion
		for k, v := range settings {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
		}
		return bi, true
	}
}

func noBuildInfo() (*debug.BuildInfo, bool) { return nil, false }

func TestResolveStampPrefersLdflags(t *testing.T) {
	got := resolveStamp("0.1.0", "abcdef1234567890", "2026-09-02T00:00:00Z",
		fakeBuildInfo(map[string]string{"vcs.revision": "ignored", "vcs.time": "ignored"}, "v9.9.9"))

	if got.version != "0.1.0" || got.commit != "abcdef1234567890" || got.date != "2026-09-02T00:00:00Z" {
		t.Errorf("ldflags values were overridden by the VCS stamp: %+v", got)
	}
}

// A `go build` with no ldflags must still report something true, because that
// is what a user who built from source is running.
func TestResolveStampFallsBackToVCSStamp(t *testing.T) {
	got := resolveStamp("", "", "",
		fakeBuildInfo(map[string]string{
			"vcs.revision": "0123456789abcdef0123",
			"vcs.time":     "2026-09-01T10:00:00Z",
			"vcs.modified": "true",
		}, "(devel)"))

	if got.commit != "0123456789abcdef0123" || got.date != "2026-09-01T10:00:00Z" {
		t.Errorf("VCS stamp not used: %+v", got)
	}
	if !got.dirty {
		t.Error("vcs.modified=true must set dirty; a dirty binary matches no published checksum")
	}
	if got.version != devVer {
		t.Errorf("version = %q, want %q for a (devel) build", got.version, devVer)
	}
}

func TestResolveStampUsesModuleVersionFromGoInstall(t *testing.T) {
	got := resolveStamp("", "", "", fakeBuildInfo(nil, "v0.2.0"))
	if got.version != "v0.2.0" {
		t.Errorf("version = %q, want the module version a `go install module@version` build carries", got.version)
	}
}

func TestResolveStampWithNoInformationAtAll(t *testing.T) {
	got := resolveStamp("", "", "", noBuildInfo)
	if got.version != devVer || got.commit != unknown || got.date != unknown {
		t.Errorf("stamp = %+v, want the honest placeholders", got)
	}
	if got.dirty {
		t.Error("dirty must be false when nothing is known")
	}
}

func TestShortNamesVersionCommitAndPlatform(t *testing.T) {
	got := Short()
	if !strings.HasPrefix(got, Name+" ") {
		t.Errorf("Short() = %q, want it to start with the binary name", got)
	}
	if !strings.HasSuffix(got, Platform()) {
		t.Errorf("Short() = %q, want it to end with %q", got, Platform())
	}
	if !strings.Contains(got, V()) {
		t.Errorf("Short() = %q does not contain the version %q", got, V())
	}
}

func TestShortCommit(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		unknown:                "",
		"abc123":               "abc123",
		"0123456789abcdef0123": "0123456789ab",
	}
	for in, want := range cases {
		if got := shortCommit(in); got != want {
			t.Errorf("shortCommit(%q) = %q, want %q", in, got, want)
		}
	}
}

// The user agent goes to DoH resolvers on a censored line. It must not carry
// anything that distinguishes one user's build from another's.
func TestUserAgentIsNotFingerprintable(t *testing.T) {
	ua := UserAgent()
	if ua != Name+"/"+V() {
		t.Errorf("UserAgent() = %q, want %q", ua, Name+"/"+V())
	}
	if strings.Contains(ua, C()) && C() != unknown {
		t.Error("the user agent must not carry the commit hash")
	}
	if strings.Contains(ua, runtime.GOARCH) {
		t.Error("the user agent must not carry the platform")
	}
}

func TestAccessorsAreStable(t *testing.T) {
	// load() memoises; a second call must not change the answer.
	if V() != V() || C() != C() || D() != D() || Dirty() != Dirty() {
		t.Error("accessors are not stable across calls")
	}
	if D() == "" || C() == "" || V() == "" {
		t.Error("accessors must never return an empty string")
	}
}

func TestPlatform(t *testing.T) {
	if got, want := Platform(), runtime.GOOS+"/"+runtime.GOARCH; got != want {
		t.Errorf("Platform() = %q, want %q", got, want)
	}
}
