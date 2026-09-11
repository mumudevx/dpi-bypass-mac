package cliapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// runScope executes one `dpb scope ...` invocation and returns stdout.
func runScope(t *testing.T, g *globals, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	g.env.Stdout = out
	g.env.Stderr = out
	root := newRoot(g)
	root.SetArgs(append([]string{"scope"}, args...))
	root.SetOut(out)
	root.SetErr(out)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func scopeGlobals(t *testing.T) *globals {
	t.Helper()
	layout := tempLayout(t)
	return &globals{
		env:    Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		layout: &layout,
		getenv: func(string) string { return "" },
	}
}

func TestScopeListPrintsCompiledInRulesWithTheirCitations(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	out, err := runScope(t, g, "list")
	if err != nil {
		t.Fatalf("scope list: %v", err)
	}
	if !strings.Contains(out, "isbank.com.tr") {
		t.Fatalf("no compiled-in rule listed:\n%s", out)
	}
	if !strings.Contains(out, "compiled-in:") {
		t.Fatalf("no provenance printed:\n%s", out)
	}
	// A rule with no citation is a rule nobody can argue with.
	if !strings.Contains(out, "MEASUREMENTS.md 5.1") {
		t.Fatalf("no citation printed:\n%s", out)
	}
}

func TestScopeListEffectiveShowsTheBogonTable(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	plain, err := runScope(t, g, "list")
	if err != nil {
		t.Fatalf("scope list: %v", err)
	}
	if strings.Contains(plain, "192.168.0.0/16") {
		t.Fatal("the bogon table is printed without --effective")
	}
	eff, err := runScope(t, g, "list", "--effective")
	if err != nil {
		t.Fatalf("scope list --effective: %v", err)
	}
	// The table is applied by policy itself and appears in no config, so
	// --effective is the only way to see what is really enforced.
	if !strings.Contains(eff, "192.168.0.0/16") {
		t.Fatalf("--effective does not show the compiled-in private-address table:\n%s", eff)
	}
}

func TestScopeBypassWritesItsOwnFileAndIsPickedUp(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	if _, err := runScope(t, g, "bypass", "example.org"); err != nil {
		t.Fatalf("scope bypass: %v", err)
	}
	layout, _ := g.layoutOf()
	data, err := os.ReadFile(scopeFile(layout))
	if err != nil {
		t.Fatalf("read scope.toml: %v", err)
	}
	if !strings.Contains(string(data), `"example.org"`) {
		t.Fatalf("scope.toml = %s", data)
	}
	// The user's own config.toml must be untouched: rewriting a hand-written
	// file would eat its comments the first time somebody typed this command.
	if _, err := os.Stat(layout.ConfigFile()); !os.IsNotExist(err) {
		t.Fatal("scope wrote to the user's config.toml")
	}

	out, err := runScope(t, g, "list")
	if err != nil {
		t.Fatalf("scope list: %v", err)
	}
	if !strings.Contains(out, "example.org") {
		t.Fatalf("the new rule is not in force:\n%s", out)
	}
}

// The compiled-in list is extendable and not removable. This is the refusal
// that makes that true, and it is exit code 5 rather than a plain error: we
// understood the request and declined it.
func TestScopeUnbypassRefusesACompiledInHost(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	out, err := runScope(t, g, "unbypass", "isbank.com.tr")
	if err == nil {
		t.Fatalf("a compiled-in bypass was removed:\n%s", out)
	}
	if !strings.Contains(err.Error(), "not removable") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "MEASUREMENTS.md 5.1") {
		t.Fatalf("the refusal cites nothing: %v", err)
	}
	var re refusedError
	if !errors.As(err, &re) {
		t.Fatalf("err = %T, want a refusal (exit code 5)", err)
	}
}

func TestScopeBypassOfACompiledInHostIsANoOp(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	out, err := runScope(t, g, "bypass", "gib.gov.tr")
	if err != nil {
		t.Fatalf("scope bypass: %v", err)
	}
	if !strings.Contains(out, "already bypassed") {
		t.Fatalf("out = %q", out)
	}
	layout, _ := g.layoutOf()
	if _, err := os.Stat(scopeFile(layout)); !os.IsNotExist(err) {
		t.Fatal("a no-op edit wrote a file")
	}
}

func TestScopeIncludeRoundTrips(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	if _, err := runScope(t, g, "add", "discord.com"); err != nil {
		t.Fatalf("scope add: %v", err)
	}
	out, err := runScope(t, g, "list")
	if err != nil {
		t.Fatalf("scope list: %v", err)
	}
	if !strings.Contains(out, "watch") || !strings.Contains(out, "discord.com") {
		t.Fatalf("include rule missing:\n%s", out)
	}
	if _, err := runScope(t, g, "remove", "discord.com"); err != nil {
		t.Fatalf("scope remove: %v", err)
	}
	out, err = runScope(t, g, "list")
	if err != nil {
		t.Fatalf("scope list: %v", err)
	}
	if strings.Contains(out, "discord.com") {
		t.Fatalf("the include rule survived removal:\n%s", out)
	}
}

func TestScopeRejectsAPatternThatCanNeverMatch(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	if _, err := runScope(t, g, "add", "*"); err == nil {
		t.Fatal("a malformed pattern was accepted")
	}
}

func TestScopeTestExplainsTheDecision(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	out, err := runScope(t, g, "test", "www.isbank.com.tr")
	if err != nil {
		t.Fatalf("scope test: %v", err)
	}
	if !strings.Contains(out, "bypass") {
		t.Fatalf("the decision is not printed:\n%s", out)
	}
	// A host watched on 443 is relayed directly on 8443; the answer has to say
	// which port it is about or the two readings look like a contradiction.
	if !strings.Contains(out, "port 443") {
		t.Fatalf("the port is not named:\n%s", out)
	}
}

func TestScopeTestOnAnUnknownHostReportsWatch(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	out, err := runScope(t, g, "test", "example.com")
	if err != nil {
		t.Fatalf("scope test: %v", err)
	}
	if !strings.Contains(out, "port 443: watch") {
		t.Fatalf("out = %s", out)
	}
}

func TestScopeRejectsAHandEditedFileItDoesNotUnderstand(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	layout, _ := g.layoutOf()
	if err := layout.EnsureDirs(); err != nil {
		t.Fatalf("dirs: %v", err)
	}
	if err := os.WriteFile(scopeFile(layout), []byte("mode = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := runScope(t, g, "bypass", "example.org"); err == nil {
		t.Fatal("a key dpb never writes was accepted in its own file")
	}
}
