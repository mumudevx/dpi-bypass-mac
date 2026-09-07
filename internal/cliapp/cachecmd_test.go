package cliapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/policy"
)

// seedCache writes a store with one desync winner and one "plain works", which
// are the two halves MEASUREMENTS.md §5.2 requires to be cached equally
// durably: a bank must be desynced at most once, ever.
func seedCache(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "verdicts.json")
	s, err := policy.OpenStore(path, time.Now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := s.Put(policy.NetworkID{}, "discord.com", policy.Verdict{
		Class:   policy.ScopeWatch,
		Spec:    "tlsfrag:pos=snimid",
		Source:  policy.SrcLearnedDesync,
		Learned: time.Now(),
		Expires: time.Now().Add(7 * 24 * time.Hour),
		Wins:    3,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(policy.NetworkID{}, "www.isbank.com.tr", policy.Verdict{
		Class:   policy.ScopeWatch,
		Source:  policy.SrcLearnedPlain,
		Learned: time.Now(),
		Wins:    1,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func TestCacheListShowsBothHalves(t *testing.T) {
	path := seedCache(t)
	r := run(t, "cache", "list", "--store", path)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{
		"discord.com", "tlsfrag:pos=snimid", "learned-desync",
		"www.isbank.com.tr", "plain", "learned-plain", "never",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("cache list is missing %q:\n%s", want, r.stdout)
		}
	}
}

func TestCacheListOnAnEmptyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdicts.json")
	r := run(t, "cache", "list", "--store", path)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "nothing learned yet") {
		t.Errorf("an empty store does not read as empty:\n%s", r.stdout)
	}
}

func TestCacheForget(t *testing.T) {
	path := seedCache(t)
	r := run(t, "cache", "forget", "discord.com", "--store", path)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	after := run(t, "cache", "list", "--store", path)
	if strings.Contains(after.stdout, "discord.com") {
		t.Errorf("discord.com survived forget:\n%s", after.stdout)
	}
	if !strings.Contains(after.stdout, "www.isbank.com.tr") {
		t.Errorf("forget removed more than the named host:\n%s", after.stdout)
	}
}

// TestCacheClearNeedsConfirmation: this deletes everything the tool learned, so
// it must not happen from a typo.
func TestCacheClearNeedsConfirmation(t *testing.T) {
	path := seedCache(t)
	r := run(t, "cache", "clear", "--store", path)
	if r.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d\n%s", r.code, ExitUsage, r.stderr)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the store was deleted without confirmation: %v", err)
	}

	r = run(t, "cache", "clear", "--store", path, "--yes")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("--yes did not delete the store")
	}
	// Clearing an already-absent store is not an error: the end state is what
	// was asked for.
	if r := run(t, "cache", "clear", "--store", path, "--yes"); r.code != ExitOK {
		t.Errorf("clearing an absent store = %d\n%s", r.code, r.stderr)
	}
}

func TestCacheExport(t *testing.T) {
	path := seedCache(t)
	r := run(t, "cache", "export", "--store", path)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "discord.com") || !strings.Contains(r.stdout, "\"networks\"") {
		t.Errorf("export did not print the store:\n%s", r.stdout)
	}
	absent := run(t, "cache", "export", "--store", filepath.Join(t.TempDir(), "none.json"))
	if strings.TrimSpace(absent.stdout) != "{}" {
		t.Errorf("exporting an absent store printed %q", absent.stdout)
	}
}

func TestCacheNeedsASubcommand(t *testing.T) {
	if r := run(t, "cache"); r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
}
