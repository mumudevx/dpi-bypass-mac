//go:build windows

package cliapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCaptureSysconfWritesAllThreeFixtures exercises the real command on the
// real machine this test runs on — the windows-latest CI runner, once this
// branch's job picks it up, same as every other windows-tagged test in this
// tree. It does not assert on the CONTENT of any capture (a CI runner's
// routing table and proxy configuration are not this project's to pin), only
// that each file lands and is valid JSON — the same bar
// scwindows/capture_test.go's on-machine tests hold the underlying calls to.
func TestCaptureSysconfWritesAllThreeFixtures(t *testing.T) {
	dir := t.TempDir()
	r := run(t, "devtool", "capture-sysconf", "--out", dir)
	if r.code != 0 {
		t.Fatalf("exit code = %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}

	for _, name := range []string{"routes.json", "adapters.json", "proxy.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Errorf("%s is not valid JSON: %v\n%s", name, err, b)
		}
	}
}
