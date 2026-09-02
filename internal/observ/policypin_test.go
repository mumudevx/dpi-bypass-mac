package observ_test

import (
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// observ sits BELOW policy in the import graph — policy publishes to observ, so
// observ cannot import it — and the drift detector nevertheless has to know
// which scope classes it is allowed to escalate. It spells the four names out
// as constants, and this test is the mechanical pin that keeps them honest.
//
// It lives in package observ_test, which is where importing policy is legal.
// Without it, renaming policy.ScopeWatch's String() would silently make
// judged() return false for every flow: the drift detector's denominator would
// go to zero, drift would never fire again, and no test in either package would
// notice.
func TestScopeNamesMatchPolicy(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want policy.ScopeClass
	}{
		{"bypass", observ.ScopeBypass, policy.ScopeBypass},
		{"direct", observ.ScopeDirect, policy.ScopeDirect},
		{"watch", observ.ScopeWatch, policy.ScopeWatch},
		{"desync", observ.ScopeDesync, policy.ScopeDesync},
	}
	for _, tc := range cases {
		if tc.got != tc.want.String() {
			t.Errorf("observ.Scope%s = %q but policy renders it %q; the drift detector "+
				"filters on this string", tc.name, tc.got, tc.want.String())
		}
	}
	// And the four must be distinct, so a copy-paste cannot make two of them the
	// same value and quietly collapse two classes into one.
	seen := map[string]bool{}
	for _, tc := range cases {
		if seen[tc.got] {
			t.Errorf("two scope constants share the value %q", tc.got)
		}
		seen[tc.got] = true
	}
}

// The drift detector counts a connection as successful by comparing
// ConnEvent.Outcome to this constant, and proxyfe is what sets it. A rename on
// either side would make every flow count as failed while every test that
// checks totals still passed.
func TestOutcomeOKIsWhatTheFrontEndSets(t *testing.T) {
	if observ.OutcomeOK != "ok" {
		t.Fatalf("observ.OutcomeOK = %q; internal/front/proxyfe's finish() sets %q on success",
			observ.OutcomeOK, "ok")
	}
}

// Sub.Name labels a subscriber in the diagnostics about dropped events, which
// is the only place a `dpb status` reader learns that a view is incomplete.
func TestSubNameIsCarried(t *testing.T) {
	b := observ.NewBus()
	defer b.Close()
	s := b.Subscribe("status --watch", 1)
	defer b.Unsubscribe(s)
	if s.Name() != "status --watch" {
		t.Fatalf("Name = %q", s.Name())
	}
}
