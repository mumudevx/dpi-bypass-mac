//go:build !windows

package cliapp

import (
	"os"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/buildinfo"
)

// TestCaptureSysconfRefusesByNameOffWindows pins devtool_other.go's contract:
// a platform this command cannot serve names itself and names the platform,
// rather than exiting 0 having written nothing — see runCaptureSysconf's own
// doc comment for why a quiet no-op is the failure mode being avoided.
func TestCaptureSysconfRefusesByNameOffWindows(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := run(t, "devtool", "capture-sysconf", "--out", dir)
	if r.code == 0 {
		t.Fatalf("exit code = 0, want a failure on %s", buildinfo.Platform())
	}
	for _, want := range []string{"capture-sysconf", "windows only", buildinfo.Platform()} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", r.stderr, want)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Errorf("--out %s must stay empty on refusal, got %v", dir, entries)
	}
}
