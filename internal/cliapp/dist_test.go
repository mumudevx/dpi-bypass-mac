package cliapp

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/buildinfo"
)

// The distribution files are three documents that have to agree with each
// other and with the code, and nothing at build time makes them.
//
// The previous tree shipped a README whose headline install command 404'd for
// its entire life: the tap did not exist, there was no release, and the formula
// still carried a placeholder checksum. Nobody noticed because no test could.
// These tests are the smallest thing that would have.
//
// They are deliberately textual. Parsing the YAML would need a dependency the
// module does not have, and the failure they exist to catch — one file edited
// and the other not — is visible in the text.

func repoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func findAll(t *testing.T, body, pattern string) [][]string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindAllStringSubmatch(body, -1)
	if m == nil {
		t.Fatalf("nothing in the file matched %s", pattern)
	}
	return m
}

// A release whose ldflags name a variable buildinfo no longer has still builds,
// still passes every test, and reports its version as the module pseudo-version
// — so `dpb version` disagrees with the tag it was cut from and no user can
// tell which binary they have. Referencing the variables here means a rename in
// buildinfo breaks this test's compilation.
func TestReleaseConfigStampsTheVariablesVersionPrints(t *testing.T) {
	t.Parallel()
	const pkg = "github.com/mumudevx/dpb/internal/buildinfo"

	stamped := map[string]*string{
		"Version": &buildinfo.Version,
		"Commit":  &buildinfo.Commit,
		"Date":    &buildinfo.Date,
	}

	seen := map[string]bool{}
	for _, m := range findAll(t, repoFile(t, ".goreleaser.yaml"), `-X\s+([\w./-]+)\.(\w+)=`) {
		if m[1] != pkg {
			t.Errorf("-X stamps %s, want %s", m[1], pkg)
			continue
		}
		if _, ok := stamped[m[2]]; !ok {
			t.Errorf("-X stamps %s.%s, which is not a variable buildinfo exports", m[1], m[2])
		}
		seen[m[2]] = true
	}
	for name := range stamped {
		if !seen[name] {
			t.Errorf("the release config does not stamp buildinfo.%s, so `dpb version` "+
				"will report the fallback for it", name)
		}
	}
}

// The Makefile builds the same three variables. If the two drift, a locally
// built binary and a released one report their identity differently, and a bug
// report stops being reproducible.
func TestMakefileAndReleaseConfigStampTheSameVariables(t *testing.T) {
	t.Parallel()
	names := func(body string) map[string]bool {
		out := map[string]bool{}
		for _, m := range findAll(t, body, `-X\s+[\w./$()-]+/internal/buildinfo\.(\w+)=`) {
			out[m[1]] = true
		}
		return out
	}
	mk, gr := names(repoFile(t, "Makefile")), names(repoFile(t, ".goreleaser.yaml"))
	for n := range gr {
		if !mk[n] {
			t.Errorf("the release config stamps buildinfo.%s and the Makefile does not", n)
		}
	}
	for n := range mk {
		if !gr[n] {
			t.Errorf("the Makefile stamps buildinfo.%s and the release config does not", n)
		}
	}
}

// renderArchiveName expands a goreleaser name_template for one GOARCH.
func renderArchiveName(tmpl, project, version, arch string) string {
	return regexp.MustCompile(`{{\s*\.(\w+)\s*}}`).ReplaceAllStringFunc(tmpl, func(s string) string {
		switch {
		case strings.Contains(s, "ProjectName"):
			return project
		case strings.Contains(s, "Version"):
			return version
		case strings.Contains(s, "Os"):
			return "darwin"
		case strings.Contains(s, "Arch"):
			return arch
		}
		return s
	})
}

// This is the test that would have caught the shipped 404. The formula names
// the files the release publishes; if the archive name template changes and the
// formula does not, `brew install dpb` downloads nothing.
func TestFormulaURLsMatchTheArchivesTheReleaseWillPublish(t *testing.T) {
	t.Parallel()
	gr := repoFile(t, ".goreleaser.yaml")
	formula := repoFile(t, "Formula/dpb.rb")

	project := findAll(t, gr, `(?m)^project_name:\s*(\S+)`)[0][1]

	// The archives section is the only name_template mentioning .Os; the
	// checksum file's is a fixed name.
	var tmpl string
	for _, m := range findAll(t, gr, `name_template:\s*"([^"]+)"`) {
		if strings.Contains(m[1], ".Os") {
			tmpl = m[1]
		}
	}
	if tmpl == "" {
		t.Fatal("no per-platform archive name_template in .goreleaser.yaml")
	}
	if !regexp.MustCompile(`formats:\s*\[\s*tar\.gz\s*\]`).MatchString(gr) {
		t.Fatal("the archive format is no longer tar.gz; the formula's URLs still say it is")
	}

	version := findAll(t, formula, `(?m)^\s*version\s+"([^"]+)"`)[0][1]
	urls := findAll(t, formula, `url\s+"([^"]+)"`)
	if len(urls) != 2 {
		t.Fatalf("formula has %d url stanzas, want one for arm64 and one for amd64", len(urls))
	}

	for i, arch := range []string{"arm64", "amd64"} {
		// The Go module path is github.com/mumudevx/dpb, but the GitHub repository
		// slug is still github.com/mumudevx/dpi-bypass-mac — they diverged when we
		// renamed the module as preparation for Windows support, but the repository
		// itself was not renamed. The formula URL must follow .goreleaser.yaml's
		// release.github.name, which points to the actual repository location.
		want := fmt.Sprintf(
			"https://github.com/mumudevx/dpi-bypass-mac/releases/download/v%s/%s.tar.gz",
			version, renderArchiveName(tmpl, project, version, arch))
		if urls[i][1] != want {
			t.Errorf("formula url %d:\n got %s\nwant %s", i, urls[i][1], want)
		}
	}
}

// A formula whose sha256 lines have been filled in for a different version than
// its url lines installs the wrong binary or fails to install at all. Both
// halves have to move together, so both are checked against one version string.
func TestFormulaVersionAgreesWithItsURLs(t *testing.T) {
	t.Parallel()
	formula := repoFile(t, "Formula/dpb.rb")
	version := findAll(t, formula, `(?m)^\s*version\s+"([^"]+)"`)[0][1]

	for _, m := range findAll(t, formula, `url\s+"([^"]+)"`) {
		if !strings.Contains(m[1], "/v"+version+"/") || !strings.Contains(m[1], "_"+version+"_") {
			t.Errorf("url %s does not belong to version %s", m[1], version)
		}
	}
	// Two checksums, one per architecture. Placeholders are expected until a
	// release is cut; what must never happen is one filled in and one not,
	// which installs on one machine and fails on the other.
	sums := findAll(t, formula, `sha256\s+"([^"]+)"`)
	if len(sums) != 2 {
		t.Fatalf("formula has %d sha256 lines, want 2", len(sums))
	}
	real := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if real.MatchString(sums[0][1]) != real.MatchString(sums[1][1]) {
		t.Errorf("one checksum is filled in and the other is not: %q / %q", sums[0][1], sums[1][1])
	}
}

// The tap the README tells people to add has to be the repository the release
// pipeline writes the formula into. `brew tap mumudevx/tap` is Homebrew's
// shorthand for github.com/mumudevx/homebrew-tap.
func TestReadmeInstallCommandNamesTheTapTheReleasePublishesTo(t *testing.T) {
	t.Parallel()
	gr := repoFile(t, ".goreleaser.yaml")
	readme := repoFile(t, "README.md")

	owner := findAll(t, gr, `(?m)^\s+owner:\s*(\S+)`)[0][1]
	var repo string
	for _, m := range findAll(t, gr, `(?m)^\s+name:\s*(\S+)`) {
		if strings.HasPrefix(m[1], "homebrew-") {
			repo = m[1]
		}
	}
	if repo == "" {
		t.Fatal("no homebrew-* repository in .goreleaser.yaml's brews section")
	}
	want := fmt.Sprintf("brew tap %s/%s", owner, strings.TrimPrefix(repo, "homebrew-"))
	if !strings.Contains(readme, want) {
		t.Errorf("README does not tell people to `%s`", want)
	}
}

// The formula must not carry a `service` block. Homebrew's would write a second
// LaunchAgent for the same binary alongside the one `dpb service install`
// writes, and two supervisors race for the same listening port and for the same
// system proxy setting — the loser's teardown restores the proxy the winner had
// just set.
func TestNothingShipsASecondLaunchdSupervisor(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Formula/dpb.rb", ".goreleaser.yaml"} {
		body := repoFile(t, name)
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if trimmed == "service do" || strings.HasPrefix(trimmed, "service: ") ||
				trimmed == "service: |" {
				t.Errorf("%s declares a Homebrew service block: %q", name, trimmed)
			}
		}
	}
}
