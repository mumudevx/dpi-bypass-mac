package policy

import (
	"strings"
	"testing"
)

// The four cases the plan pins by name. MEASUREMENTS.md §5.1 lists ten
// Turkish banks and .gov.tr sites that break under the winning emitter, so a
// bypass rule for one of them firing on an attacker-chosen lookalike — or,
// worse, failing to fire on the real thing — is the failure mode that costs a
// user their bank session.
func TestMatchLabelIsAnchoredOnALabelBoundary(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"bank.com", true},
		{"www.bank.com", true},
		{"a.b.c.bank.com", true},
		{"BANK.COM", true},
		{"www.bank.com.", true},
		{"  www.bank.com  ", true},

		{"evilbank.com", false},
		{"xbank.com", false},
		{"bank.com.evil.tld", false},
		{"bank.commerce.com", false},
		{"notbank.com", false},
		{"bank.co", false},
		{"", false},
		{".bank.com", false}, // an empty leading label is not a hostname
	}
	for _, c := range cases {
		if got := MatchLabel("bank.com", c.host); got != c.want {
			t.Errorf("MatchLabel(%q, %q) = %v, want %v", "bank.com", c.host, got, c.want)
		}
	}
}

func TestMatchLabelPatternForms(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		// Leading dot is a spelling convenience for the anchored form; the
		// compiled-in list writes ".gov.tr" and ".com.tr" that way.
		{".gov.tr", "turkiye.gov.tr", true},
		{".gov.tr", "gov.tr", true},
		{".gov.tr", "notgov.tr", false},
		{".com.tr", "isbank.com.tr", true},
		{".com.tr", "isbank.com", false},

		// Wildcard: subdomains only.
		{"*.bank.com", "www.bank.com", true},
		{"*.bank.com", "bank.com", false},
		{"*.bank.com", "evilbank.com", false},

		// Exact: no subdomains.
		{"=bank.com", "bank.com", true},
		{"=bank.com", "www.bank.com", false},

		// Rejected pattern forms match nothing rather than matching loosely.
		{"", "bank.com", false},
		{"ba*nk.com", "bank.com", false},
		{"bank.*", "bank.com", false},
		{"10.0.0.0/8", "10.0.0.1", false},
		{"1.2.3.4", "1.2.3.4", false},
	}
	for _, c := range cases {
		if got := MatchLabel(c.pattern, c.host); got != c.want {
			t.Errorf("MatchLabel(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Discord.com", "discord.com"},
		{"discord.com.", "discord.com"},
		{"  DISCORD.COM. ", "discord.com"},
		{"", ""},
		{".", ""},
		{"..", ""},
		{"a..b", ""},
		{"host name", ""},
		{"host/name", ""},
		{"host:443", ""},
		{"1.2.3.4", "1.2.3.4"},
		{"::ffff:1.2.3.4", "1.2.3.4"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:DB8::1", "2001:db8::1"},
		// Punycode: a Turkish IDN rule must match the A-label form the wire
		// actually carries.
		{"türkiye.gov.tr", "xn--trkiye-3ya.gov.tr"},
		{"XN--TRKIYE-3YA.gov.tr", "xn--trkiye-3ya.gov.tr"},
		{strings.Repeat("a", 64) + ".com", ""},
		{strings.Repeat("a.", 200) + "com", ""},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A Unicode rule and a punycode host are the same name; if they do not
// normalise together the rule silently protects nobody.
func TestMatchLabelUnicodeAndPunycodeAgree(t *testing.T) {
	if !MatchLabel("türkiye.gov.tr", "www.xn--trkiye-3ya.gov.tr") {
		t.Error("unicode pattern did not match its punycode host")
	}
	if !MatchLabel("xn--trkiye-3ya.gov.tr", "TÜRKIYE.gov.tr") {
		t.Error("punycode pattern did not match its unicode host")
	}
	if MatchLabel("türkiye.gov.tr", "eviltürkiye.gov.tr") {
		t.Error("unicode pattern matched across a label boundary")
	}
}

func TestNewMatcherRejectsAddressPatterns(t *testing.T) {
	for _, p := range []string{"10.0.0.0/8", "192.168.1.1", "::1", "", "*", "a**b.com"} {
		if _, err := NewMatcher([]Rule{{Pattern: p, From: "cfg", Line: 3}}); err == nil {
			t.Errorf("NewMatcher(%q) succeeded, want an error naming the pattern", p)
		} else if !strings.Contains(err.Error(), "cfg:3") {
			t.Errorf("NewMatcher(%q) error %q does not carry provenance", p, err)
		}
	}
}

func TestMatcherReturnsMostSpecificFirst(t *testing.T) {
	m, err := NewMatcher([]Rule{
		{Pattern: ".com.tr", Class: ScopeBypass, From: FromCompiledIn},
		{Pattern: "isbank.com.tr", Class: ScopeBypass, From: "cfg", Line: 1},
		{Pattern: "=www.isbank.com.tr", Class: ScopeDirect, From: "cfg", Line: 2},
		{Pattern: "*.example.com", Class: ScopeWatch, From: "cfg", Line: 3},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	got := patterns(m.Match("www.isbank.com.tr"))
	want := []string{"=www.isbank.com.tr", "isbank.com.tr", ".com.tr"}
	if !equalStrings(got, want) {
		t.Errorf("Match(www.isbank.com.tr) = %v, want %v", got, want)
	}

	got = patterns(m.Match("isbank.com.tr"))
	want = []string{"isbank.com.tr", ".com.tr"}
	if !equalStrings(got, want) {
		t.Errorf("Match(isbank.com.tr) = %v, want %v", got, want)
	}

	if got := patterns(m.Match("example.com")); len(got) != 0 {
		t.Errorf("wildcard rule matched its own apex: %v", got)
	}
	if got := patterns(m.Match("a.example.com")); !equalStrings(got, []string{"*.example.com"}) {
		t.Errorf("Match(a.example.com) = %v", got)
	}
	if got := m.Match("evilisbank.com.tr"); len(got) != 1 || got[0].Pattern != ".com.tr" {
		t.Errorf("Match(evilisbank.com.tr) = %v, want only the .com.tr suffix rule", patterns(got))
	}
	if got := m.Match("nonsense"); len(got) != 0 {
		t.Errorf("Match(nonsense) = %v, want none", patterns(got))
	}
	if got := m.Match(""); len(got) != 0 {
		t.Errorf("Match(\"\") = %v, want none", patterns(got))
	}
	if m.Len() != 4 || len(m.Rules()) != 4 {
		t.Errorf("Len/Rules = %d/%d, want 4/4", m.Len(), len(m.Rules()))
	}
}

// Ties within one base name keep input order so the first line of a config
// file wins, which is what a user editing a list expects.
func TestMatcherKeepsInputOrderWithinOneBase(t *testing.T) {
	m, err := NewMatcher([]Rule{
		{Pattern: "bank.com", Class: ScopeBypass, From: "first"},
		{Pattern: ".bank.com", Class: ScopeWatch, From: "second"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	got := m.Match("bank.com")
	if len(got) != 2 || got[0].From != "first" || got[1].From != "second" {
		t.Errorf("Match order = %+v", got)
	}
}

func TestNilMatcherMatchesNothing(t *testing.T) {
	var m *Matcher
	if got := m.Match("bank.com"); got != nil {
		t.Errorf("nil Matcher matched %v", got)
	}
	if m.Len() != 0 || m.Rules() != nil {
		t.Error("nil Matcher reported rules")
	}
	empty, err := NewMatcher(nil)
	if err != nil {
		t.Fatalf("NewMatcher(nil): %v", err)
	}
	if got := empty.Match("bank.com"); got != nil {
		t.Errorf("empty Matcher matched %v", got)
	}
}

func TestRuleWhere(t *testing.T) {
	cases := []struct {
		rule Rule
		want string
	}{
		{Rule{From: "cfg", Line: 31}, "cfg:31"},
		{Rule{From: FromCompiledIn}, "compiled-in"},
		{Rule{}, "unknown"},
	}
	for _, c := range cases {
		if got := c.rule.Where(); got != c.want {
			t.Errorf("Where(%+v) = %q, want %q", c.rule, got, c.want)
		}
	}
}

func TestPunycodeEncoderMatchesKnownVectors(t *testing.T) {
	// Known-good A-labels, including the Turkish spelling this tool is
	// actually for.
	cases := []struct{ in, want string }{
		{"bücher", "xn--bcher-kva"},
		{"türkiye", "xn--trkiye-3ya"},
		{"münchen", "xn--mnchen-3ya"},
		{"ü", "xn--tda"},
	}
	for _, c := range cases {
		got, err := punyEncode(c.in)
		if err != nil {
			t.Fatalf("punyEncode(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("punyEncode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := punyEncode(strings.Repeat("ü", maxLabelRunes+1)); err == nil {
		t.Error("punyEncode accepted an over-long label")
	}
	if got := Normalize("a\xffb.com"); got != "" {
		t.Errorf("Normalize of invalid UTF-8 = %q, want \"\"", got)
	}
}

func patterns(rs []Rule) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Pattern
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Normalize runs on the connection path against a peer-supplied SNI or CONNECT
// target, so its cost must not scale with whatever the peer sent.
func TestNormalizeRejectsOversizedInputEarly(t *testing.T) {
	huge := strings.Repeat("ü.", 1<<16)
	if got := Normalize(huge); got != "" {
		t.Errorf("Normalize accepted a %d-byte input: %q", len(huge), got)
	}
	if MatchLabel("bank.com", huge) {
		t.Error("an oversized input matched a rule")
	}
	// The bound is above any real name: the longest legal hostname still
	// normalises.
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." +
		strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".tr"
	if len(long) > maxNameLen {
		t.Fatalf("test name is %d bytes, longer than a legal hostname", len(long))
	}
	if Normalize(long) != long {
		t.Errorf("Normalize rejected a legal %d-byte hostname", len(long))
	}
}
