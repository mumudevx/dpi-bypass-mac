//go:build windows

// This file tests validateTunName's Windows rule — a wintun adapter's
// friendly name — the way tunname_test.go tests darwin's utunN rule. The two
// live in separate, platform-tagged files because tunname_darwin.go and
// tunname_windows.go each define their own validateTunName with a different
// rule; a table built from one platform's valid and invalid names asserts
// nothing about the other's.
//
// Nothing here can be executed in this environment — there is no Windows
// machine to run it on — but `GOOS=windows go vet ./...` type-checks it, and
// the regex and the CLI wiring it exercises are the same ones a real Windows
// run would use.

package cliapp

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestTunNameMustBeAWindowsFriendlyName is tunname_test.go's
// TestTunNameMustBeAUtun for the other platform: the names a wintun adapter's
// friendly name may and may not take.
func TestTunNameMustBeAWindowsFriendlyName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"dpb", true},    // the default
		{"My VPN", true}, // spaces are fine; this is a friendly name, not a unit
		{"utun", true},   // valid here too — just not special the way it is on macOS
		{"", false},      // an explicitly empty flag is not the default
		{`back\slash`, false},
		{"for/ward", false},
		{"colon:name", false},
		{"star*name", false},
		{"question?name", false},
		{`quote"name`, false},
		{"less<than", false},
		{"greater>than", false},
		{"pipe|name", false},
		{"control\x01char", false},
		{strings.Repeat("x", 127), true},  // at wintun's AdapterNameMax, minus its own NUL
		{strings.Repeat("x", 128), false}, // one past it
	} {
		err := validateTunName(tc.name)
		if tc.ok && err != nil {
			t.Errorf("--tun-name %q was refused: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("--tun-name %q was accepted; wintun's CreateAdapter would not take it, "+
				"or Windows would refuse the resulting connection name later", tc.name)
		}
	}
}

// TestTunNameWithAReservedCharacterIsRefusedBeforeAnyPlanExists is
// tunname_test.go's TestTunNameOnARealInterfaceIsRefusedBeforeAnyPlanExists
// for the other platform: it drives the shipped command over a name Windows
// itself would refuse for a network connection, and checks the refusal names
// the platform the user is actually on — the whole point of Finding 1, since
// the old, untagged rule refused every Windows name with a message about
// macOS.
func TestTunNameWithAReservedCharacterIsRefusedBeforeAnyPlanExists(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = false

	mac := newFakeMac()
	var out, errOut bytes.Buffer
	g := &globals{
		env:    Env{Stdout: &out, Stderr: &errOut},
		layout: &layout,
		runner: mac,
		rib:    mac,
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--tun", "--tun-name", "bad:name", "--dry-run",
		"--proxy-style", "none", "--port", "0", "--socks-port", fmt.Sprint(freePort(t))})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})

	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("dpb run --tun --tun-name bad:name --dry-run succeeded; Windows would have " +
			"refused that connection name")
	}
	if got := exitCodeFor(err); got != ExitUsage {
		t.Fatalf("exit code %d, want %d (ExitUsage): a bad flag value is a usage error",
			got, ExitUsage)
	}
	msg := err.Error()
	if !strings.Contains(msg, "bad:name") {
		t.Errorf("the refusal does not name the value that was asked for:\n%s", msg)
	}
	if !strings.Contains(msg, "Windows") {
		t.Errorf("the refusal does not name the platform the user is on:\n%s", msg)
	}
	// And no plan was printed. A refused name must not leave a description of
	// what dpb "would" do under it on the user's terminal.
	if s := out.String(); strings.Contains(s, "bad:name") {
		t.Fatalf("a plan naming bad:name was printed anyway:\n%s", s)
	}
}
