//go:build !windows

// TestRunPicksUpScopeEdits drives the shipped `run` command through startRun,
// which spawns fakeDPBBinary — a /bin/sh script standing in for the dpb
// executable the janitor child would otherwise be — so it carries the same
// tag as run_test.go, where startRun is defined. The rest of scope_test.go
// only needs runScope and scopeGlobals, which touch no process, so this one
// test is the only reason that file used to need the tag too.

package cliapp

import (
	"strings"
	"testing"
)

// `dpb run` must see the same rules `dpb scope` writes, or the two commands
// disagree about what the tool is doing.
func TestRunPicksUpScopeEdits(t *testing.T) {
	t.Parallel()
	g := scopeGlobals(t)
	if _, err := runScope(t, g, "bypass", "example.org"); err != nil {
		t.Fatalf("scope bypass: %v", err)
	}
	layout, _ := g.layoutOf()

	mac := newFakeMac()
	h := startRun(t, mac, layout, "--proxy-style", "none")
	pac := fetchDirect(t, "http://"+h.addr()+"/dpb.pac")
	if !strings.Contains(pac, `"example.org"`) {
		t.Fatalf("the running proxy does not carry the scope edit:\n%s", pac)
	}
}
