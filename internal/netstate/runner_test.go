package netstate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return strings.TrimRight(string(b), "\n")
}

// TestExecRunner and TestExecRunnerContextCancel moved to runner_unix_test.go.
// See the build-tag comment there for why the absolute /bin/... argv they name
// cannot be run on Windows, and runner_windows_test.go for the same properties
// asserted through cmd.exe.

func TestNoRunnerFailsLoudly(t *testing.T) {
	res := Env{}.runner().Run(context.Background(), "route", "add")
	if !res.Failed() || res.Err == nil {
		t.Fatalf("a zero Env must fail explicitly, got %+v", res)
	}
	if !strings.Contains(res.Reason(), "Runner is nil") {
		t.Fatalf("Reason() = %q, want it to name the nil Runner", res.Reason())
	}
}
