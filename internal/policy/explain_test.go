package policy

import (
	"strings"
	"testing"
	"time"
)

// `dpb why www.isbank.com.tr` must print the matched compiled-in bypass rule
// with its provenance and the effective verdict. That is M12's acceptance
// criterion; the assembly it depends on lives here.
func TestExplainAttributesACompiledInBypass(t *testing.T) {
	e, _ := newTestEngine(t, func(o *EngineOptions) {
		o.Recent = func(host string) []ConnSummary {
			if host != "isbank.com.tr" {
				return nil
			}
			return []ConnSummary{{
				At:       time.Date(2026, 9, 2, 11, 59, 0, 0, time.UTC),
				Attempts: 1,
				OK:       true,
				Latency:  29 * time.Millisecond,
			}}
		}
	})

	x := e.Explain("WWW.ISBANK.COM.TR.")
	if x.Input != "WWW.ISBANK.COM.TR." {
		t.Errorf("Input = %q, want the user's own spelling", x.Input)
	}
	if x.Punycode != "www.isbank.com.tr" {
		t.Errorf("Punycode = %q", x.Punycode)
	}
	if len(x.Matched) != 2 || x.Matched[0].Pattern != "isbank.com.tr" {
		t.Fatalf("Matched = %v, want the specific rule first", patterns(x.Matched))
	}
	// The broader .com.tr suffix rule also matches and is listed after the
	// specific one; .gov.tr must not appear at all.
	if x.Matched[1].Pattern != ".com.tr" {
		t.Errorf("second match = %q, want .com.tr", x.Matched[1].Pattern)
	}
	if x.Effective.Class != ScopeBypass || x.Effective.Source != SrcBuiltinBypass {
		t.Errorf("Effective = %+v", x.Effective)
	}

	// Explain is asked for the apex, so Recent is keyed on the canonical name.
	x2 := e.Explain("isbank.com.tr")
	if len(x2.Recent) != 1 || !x2.Recent[0].OK {
		t.Errorf("Recent = %+v", x2.Recent)
	}

	var b strings.Builder
	if err := x.Text(&b); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := b.String()
	for _, want := range []string{
		"WWW.ISBANK.COM.TR.",
		"www.isbank.com.tr",
		"isbank.com.tr",
		"compiled-in",
		"bypass",
		"builtin-bypass",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered explanation is missing %q:\n%s", want, out)
		}
	}
}

func TestExplanationTextRendersEveryField(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	x := Explanation{
		Input:    "discord.com",
		Punycode: "discord.com",
		Matched: []Rule{
			{Pattern: "discord.com", Class: ScopeWatch, From: "cfg", Line: 3},
			{Pattern: ".com", Class: ScopeBypass, From: FromCompiledIn},
		},
		Effective: Verdict{
			Class:    ScopeDesync,
			Spec:     "tlsfrag:pos=snimid",
			Ladder:   []string{"", "tlsfrag:pos=snimid"},
			Source:   SrcLearnedDesync,
			Reason:   "cached",
			Learned:  now.Add(-2 * time.Hour),
			Expires:  now.Add(7 * 24 * time.Hour),
			Wins:     4,
			Losses:   1,
			RuleText: "discord.com",
			RuleFrom: "cfg:3",
		},
		Recent: []ConnSummary{
			{At: now.Add(-time.Minute), Spec: "tlsfrag:pos=snimid", Attempts: 2, OK: true, Latency: 45 * time.Millisecond},
			{At: now.Add(-2 * time.Minute), Attempts: 5, OK: false},
		},
	}
	var b strings.Builder
	if err := x.TextAt(&b, now); err != nil {
		t.Fatalf("TextAt: %v", err)
	}
	out := b.String()
	for _, want := range []string{
		"desync", "learned-desync", "tlsfrag:pos=snimid",
		"plain -> tlsfrag:pos=snimid", // the empty spec must render as "plain"
		"2h0m0s ago", "in 168h0m0s",
		"4 ok, 1 failed",
		"45ms", "failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "normalised:") {
		t.Error("normalised line printed for a name that needed no normalising")
	}
}

func TestExplanationTextForNoMatchAndNeverExpires(t *testing.T) {
	x := Explanation{
		Input:     "cloudflare.com",
		Punycode:  "cloudflare.com",
		Effective: Verdict{Class: ScopeDirect, Source: SrcLearnedPlain, Reason: "cached"},
	}
	var b strings.Builder
	if err := x.Text(&b); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "none matched") {
		t.Errorf("missing the no-rules line:\n%s", out)
	}
	// A user seeing "never" should know it is deliberate.
	if !strings.Contains(out, "expires:   never") {
		t.Errorf("missing the never-expires explanation:\n%s", out)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

var errWrite = &writeError{}

type writeError struct{}

func (*writeError) Error() string { return "disk on fire" }

func TestExplanationTextWrapsWriteErrors(t *testing.T) {
	err := Explanation{Input: "x"}.Text(failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Errorf("err = %v, want the underlying write error wrapped", err)
	}
}
