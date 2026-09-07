package cliapp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/policy"
)

// whyHandler is what `dpb run` wires into observ.Handler.Why, so it is the
// thing that produces the LIVE answer. It exists in this file rather than in
// run.go precisely so the live answer and the offline answer are assembled by
// one function; these tests are what keep that claim true.

func testEngine(t *testing.T, store policy.Store, ladder []string) *policy.Engine {
	t.Helper()
	rules := []policy.Rule{
		{Pattern: "isbank.com.tr", Class: policy.ScopeBypass, From: policy.FromCompiledIn, Line: 2},
	}
	m, err := policy.NewMatcher(rules)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	set, err := policy.NewIPSet(nil)
	if err != nil {
		t.Fatalf("ipset: %v", err)
	}
	return policy.NewEngine(policy.EngineOptions{
		Rules: m, IPs: set, Store: store, Ladder: ladder,
		NetID: func() policy.NetworkID { return policy.NetworkID{Kind: "wifi"} },
	})
}

func TestWhyHandlerCarriesRuleProvenance(t *testing.T) {
	engine := testEngine(t, policy.NopStore(), []string{"", "tlsfrag:pos=snimid"})
	h := whyHandler(engine, func() policy.NetworkID { return policy.NetworkID{Kind: "wifi"} }, nil)

	w, err := h(context.Background(), "www.isbank.com.tr", 443)
	if err != nil {
		t.Fatalf("whyHandler: %v", err)
	}
	if w.Verdict.Class != "bypass" || w.Verdict.Source != "builtin-bypass" {
		t.Fatalf("verdict = %+v", w.Verdict)
	}
	if len(w.Rules) == 0 || w.Rules[0].Where != policy.FromCompiledIn+":2" {
		t.Fatalf("rules = %+v, want the file and line that decided", w.Rules)
	}
	if w.Network == "" {
		t.Error("the network the verdict was looked up under is missing")
	}
	// And the compiled-in citation must be reachable from it, which is what the
	// CLI prints under the verdict.
	if mandatoryReasonFor(w) == "" {
		t.Errorf("no compiled-in reason was reachable from the live answer: %+v", w.Rules)
	}
	if _, ok := config.MandatoryReason("isbank.com.tr"); !ok {
		t.Fatal("the fixture rule is not actually a compiled-in one")
	}
}

// A learned verdict's timestamps are the whole answer to "it worked yesterday",
// so they must survive the handler.
func TestWhyHandlerReportsALearnedVerdict(t *testing.T) {
	store, err := policy.OpenStore("", time.Now) // memory-only
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	learned := time.Now().Add(-3 * time.Hour)
	netID := policy.NetworkID{Kind: "wifi"}
	if err := store.Put(netID, "discord.com", policy.Verdict{
		Class: policy.ScopeDesync, Spec: "tlsfrag:pos=snimid",
		Source: policy.SrcLearnedDesync, Learned: learned,
		Expires: learned.Add(7 * 24 * time.Hour), Wins: 5,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	engine := testEngine(t, store, []string{"", "tlsfrag:pos=snimid"})
	h := whyHandler(engine, func() policy.NetworkID { return netID }, nil)
	w, err := h(context.Background(), "discord.com", 443)
	if err != nil {
		t.Fatalf("whyHandler: %v", err)
	}
	if w.Verdict.Source != "learned-desync" || w.Verdict.Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("verdict = %+v", w.Verdict)
	}
	if w.Verdict.Learned.IsZero() || w.Verdict.Expires.IsZero() {
		t.Fatalf("the learned/expires timestamps were lost: %+v", w.Verdict)
	}
	if w.Verdict.Wins != 5 {
		t.Errorf("the record was lost: %+v", w.Verdict)
	}
}

// The recent-connection table is where observ.Counters plugs in, and it must be
// keyed the way the counters file events: by the NORMALISED name.
func TestWhyHandlerAttachesRecentConnections(t *testing.T) {
	counters := observ.NewCounters(observ.CountersOptions{})
	counters.Observe(observ.ConnEvent{
		Time: time.Now(), Host: "discord.com", Scope: observ.ScopeWatch,
		Outcome: observ.OutcomeOK, Attempts: 2, Strategy: "tlsfrag:pos=snimid",
	})

	engine := testEngine(t, policy.NopStore(), nil)
	h := whyHandler(engine, nil, counters)

	// Typed with a trailing dot and different case: policy normalises it, and
	// the handler must look the history up under the normalised key or the
	// table silently comes back empty for half the ways a user types a name.
	w, err := h(context.Background(), "Discord.com.", 443)
	if err != nil {
		t.Fatalf("whyHandler: %v", err)
	}
	if len(w.Recent) != 1 || !w.Recent[0].OK || w.Recent[0].Attempts != 2 {
		t.Fatalf("recent = %+v", w.Recent)
	}
}

// An unnamed flow is filed under the address it dialled, and a user who types
// that address deserves the same history.
func TestWhyHandlerFindsHistoryForAnAddress(t *testing.T) {
	counters := observ.NewCounters(observ.CountersOptions{})
	counters.Observe(observ.ConnEvent{
		Time: time.Now(), Addr: "162.159.128.233:443", Scope: observ.ScopeWatch,
		Outcome: observ.OutcomeOK,
	})
	engine := testEngine(t, policy.NopStore(), nil)
	h := whyHandler(engine, nil, counters)

	w, err := h(context.Background(), "162.159.128.233:443", 443)
	if err != nil {
		t.Fatalf("whyHandler: %v", err)
	}
	if len(w.Recent) != 1 {
		t.Fatalf("recent = %+v", w.Recent)
	}
}

// Port 0 means "whatever this dpb inspects", which is what a control request
// with no port carries.
func TestWhyHandlerDefaultsThePort(t *testing.T) {
	engine := testEngine(t, policy.NopStore(), nil)
	h := whyHandler(engine, nil, nil)
	w, err := h(context.Background(), "discord.com", 0)
	if err != nil {
		t.Fatalf("whyHandler: %v", err)
	}
	if w.Port != engine.InspectPorts()[0] {
		t.Fatalf("port = %d, want the first inspect port %d", w.Port, engine.InspectPorts()[0])
	}
}

func TestWhyHandlerWithNoEngine(t *testing.T) {
	h := whyHandler(nil, nil, nil)
	if _, err := h(context.Background(), "discord.com", 443); err == nil {
		t.Fatal("a nil engine produced an answer")
	} else if !strings.Contains(err.Error(), "scope engine") {
		t.Errorf("err = %v", err)
	}
}
