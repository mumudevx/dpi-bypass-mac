package cliapp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/policy"
)

// The M12 acceptance clause: `dpb why www.isbank.com.tr` prints the matched
// compiled-in bypass rule WITH ITS PROVENANCE and the effective verdict.
//
// Provenance is the load-bearing half. A tool that says "bypass" without saying
// which rule decided and where that rule came from is asking to be trusted; one
// that names the file is offering evidence.
func TestWhyPrintsTheCompiledInBypassWithItsProvenance(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "why", "www.isbank.com.tr")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{
		"isbank.com.tr",             // the rule that matched
		policy.FromCompiledIn,       // where it came from
		"verdict:   bypass",         // the effective verdict
		"source:    builtin-bypass", // and why it holds
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output does not contain %q:\n%s", want, r.stdout)
		}
	}
	// The measured reason is what makes the veto arguable rather than arbitrary.
	if !strings.Contains(r.stdout, "compiled in:") {
		t.Errorf("no compiled-in reason was printed:\n%s", r.stdout)
	}
}

// A host with no rule falls to the default, and the default must be legible:
// what class, why, and what ladder would be walked.
func TestWhyPrintsTheDefaultAndItsLadder(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "why", "discord.com")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{"rules:     none matched", "verdict:   watch", "ladder:", "plain ->"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output does not contain %q:\n%s", want, r.stdout)
		}
	}
}

// The second half of the milestone's requirement: a LEARNED verdict must show
// when it was learned and when it expires. Without those two lines, "it worked
// yesterday" has no answer at all.
func TestWhyShowsWhenALearnedVerdictWasLearnedAndWhenItExpires(t *testing.T) {
	c := newCLI(t)

	// Seed the on-disk store under the identity `dpb why` will look up.
	netID := seedStore(t, c, "discord.com", policy.Verdict{
		Class:   policy.ScopeDesync,
		Spec:    "tlsfrag:pos=snimid",
		Source:  policy.SrcLearnedDesync,
		Learned: time.Now().Add(-2 * time.Hour),
		Expires: time.Now().Add(5 * 24 * time.Hour),
		Wins:    4,
	})
	t.Logf("seeded under network %s", netID.Key())

	r := c.exec(t, "why", "discord.com")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{
		"verdict:   desync",
		"source:    learned-desync",
		"strategy:  tlsfrag:pos=snimid",
		"learned:",
		"expires:",
		"record:    4 ok",
		"network:   " + netID.Key(),
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output does not contain %q:\n%s", want, r.stdout)
		}
	}
}

// A learned-plain verdict never expires, and saying so explicitly is the
// difference between a user reading "deliberate and self-correcting" and
// reading "somebody forgot the TTL".
func TestWhyExplainsAPlainVerdictThatNeverExpires(t *testing.T) {
	c := newCLI(t)
	seedStore(t, c, "example.com", policy.Verdict{
		Class:   policy.ScopeDirect,
		Source:  policy.SrcLearnedPlain,
		Learned: time.Now().Add(-time.Hour),
	})
	r := c.exec(t, "why", "example.com")
	if !strings.Contains(r.stdout, "expires:   never") {
		t.Errorf("a never-expiring verdict was not explained:\n%s", r.stdout)
	}
}

// With no dpb running the answer comes from disk, and it has to SAY so:
// otherwise an empty cache is indistinguishable from a daemon that has learned
// plenty and simply was not asked.
func TestWhySaysWhereTheAnswerCameFrom(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "why", "discord.com")
	if !strings.Contains(r.stdout, "no dpb is running") {
		t.Errorf("the offline answer did not say so:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "answered from: the configuration and") {
		t.Errorf("the source of the answer was not named:\n%s", r.stdout)
	}
}

// With a dpb running, the live answer wins — that is the only way a verdict
// learned since start-up and not yet flushed to disk can be seen.
func TestWhyPrefersTheRunningDPB(t *testing.T) {
	c := newCLI(t)
	learned := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	startControl(t, c.layout, observ.Handler{
		Why: func(_ context.Context, host string, port int) (observ.Why, error) {
			return observ.Why{
				Host: host, Punycode: host, Port: port, Network: "wifi-live",
				Verdict: observ.WhyVerdict{
					Class: "desync", Spec: "chunk:size=12", Source: "learned-desync",
					Learned: learned, Expires: learned.Add(7 * 24 * time.Hour),
				},
				Recent: []observ.ConnStat{{At: learned, OK: true, Attempts: 2, Spec: "chunk:size=12"}},
			}, nil
		},
	})

	r := c.exec(t, "why", "discord.com")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "answered from: the running dpb") {
		t.Errorf("the live answer was not used:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "chunk:size=12") {
		t.Errorf("the live verdict did not reach the output:\n%s", r.stdout)
	}
	// The recent-connection table is the "my bank broke" half of the command.
	if !strings.Contains(r.stdout, "recent:") {
		t.Errorf("the live answer's recent connections were dropped:\n%s", r.stdout)
	}
}

// A daemon that is there but cannot answer must not silence the command: the
// on-disk view plus a warning is strictly better than an error.
func TestWhyFallsBackWhenTheDaemonFails(t *testing.T) {
	c := newCLI(t)
	startControl(t, c.layout, observ.Handler{}) // no Why handler
	r := c.exec(t, "why", "www.isbank.com.tr")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "warning:") {
		t.Errorf("the failure was not reported:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "verdict:   bypass") {
		t.Errorf("the on-disk answer was not printed:\n%s", r.stdout)
	}
}

// The port is part of the question. A host that is watched on 443 is relayed
// directly on 8443, and answering about 443 when 8443 was asked would be the
// wrong answer printed confidently.
func TestWhyHonoursThePort(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "why", "discord.com", "--port", "8443")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "verdict:   direct") {
		t.Errorf("an uninspected port was not answered as direct:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "port:      8443") {
		t.Errorf("the port asked about was not printed:\n%s", r.stdout)
	}
}

func TestWhyRejectsAnImpossiblePort(t *testing.T) {
	c := newCLI(t)
	if r := c.exec(t, "why", "discord.com", "--port", "70000"); r.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

func TestWhyNeedsAHost(t *testing.T) {
	c := newCLI(t)
	if r := c.exec(t, "why"); r.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

func TestWhyJSON(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "why", "www.isbank.com.tr", "--json")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	var rep whyReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("decode: %v\n%s", err, r.stdout)
	}
	if rep.Host != "www.isbank.com.tr" || rep.Port != 443 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Why.Verdict.Class != "bypass" || rep.Why.Verdict.Source != "builtin-bypass" {
		t.Fatalf("verdict = %+v", rep.Why.Verdict)
	}
	if len(rep.Why.Rules) == 0 || rep.Why.Rules[0].Where == "" {
		t.Fatalf("rules carry no provenance: %+v", rep.Why.Rules)
	}
	if rep.Mandatory == "" {
		t.Error("the compiled-in reason is missing from the JSON")
	}
}

// An IP literal is a perfectly ordinary thing to type, and the bogon table must
// answer for it.
func TestWhyAcceptsAnIPLiteral(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "why", "192.168.1.1")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "verdict:   bypass") {
		t.Errorf("a private address was not vetoed:\n%s", r.stdout)
	}
}

// The live and the offline answer are rendered by the same code. A round trip
// through the wire type must not lose the provenance the command exists to
// print.
func TestWhyWireTypeRoundTrip(t *testing.T) {
	learned := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	x := policy.Explanation{
		Input:    "discord.com",
		Punycode: "discord.com",
		Matched: []policy.Rule{
			{Pattern: "discord.com", Class: policy.ScopeWatch, From: "~/.config/dpb/config.toml", Line: 31},
		},
		Effective: policy.Verdict{
			Class: policy.ScopeDesync, Spec: "tlsfrag:pos=snimid",
			Ladder: []string{"", "tlsfrag:pos=snimid"},
			Source: policy.SrcLearnedDesync, Reason: "cached",
			RuleText: "discord.com", RuleFrom: "config.toml:31",
			Learned: learned, Expires: learned.Add(7 * 24 * time.Hour),
			Wins: 3, Losses: 1,
		},
		Recent: []policy.ConnSummary{{At: learned, Spec: "tlsfrag:pos=snimid", Attempts: 2, OK: true}},
	}

	back := explanationFromWhy(whyFromExplanation(x, 443, "wifi-abc"))
	if back.Effective.Class != x.Effective.Class || back.Effective.Source != x.Effective.Source {
		t.Fatalf("class/source did not survive: %+v", back.Effective)
	}
	if !back.Effective.Learned.Equal(learned) || !back.Effective.Expires.Equal(x.Effective.Expires) {
		t.Fatalf("timestamps did not survive: %+v", back.Effective)
	}
	if len(back.Matched) != 1 || back.Matched[0].Where() != "~/.config/dpb/config.toml:31" {
		t.Fatalf("provenance did not survive: %+v", back.Matched)
	}
	if back.Effective.Wins != 3 || back.Effective.Losses != 1 {
		t.Fatalf("the record did not survive: %+v", back.Effective)
	}
	if len(back.Recent) != 1 || !back.Recent[0].OK {
		t.Fatalf("recent did not survive: %+v", back.Recent)
	}
}

// seedStore writes one verdict into the layout's store under the identity the
// command will look up, and returns that identity.
func seedStore(t *testing.T, c *cli, host string, v policy.Verdict) policy.NetworkID {
	t.Helper()
	var out bytes.Buffer
	layout := c.layout
	g := &globals{
		env:    Env{Stdout: &out, Stderr: &out},
		layout: &layout,
		runner: c.mac,
		rib:    c.mac,
		facts:  &netstate.Facts{Uplink: "en0", Services: []string{"Wi-Fi"}},
		getenv: func(string) string { return "" },
	}
	cfg, err := scopeConfig(g)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	netID, _ := g.networkIdentity(context.Background(), cfg)

	store, err := policy.OpenStore(c.layout.VerdictFile(), time.Now)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Put(netID, host, v); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	return netID
}
