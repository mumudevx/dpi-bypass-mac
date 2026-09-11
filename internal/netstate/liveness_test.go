package netstate

import "testing"

// The single rule the whole run-lock safety argument rests on: a query that did
// not conclude anything must resolve as ALIVE.
//
// The failure this pins is not hypothetical and not Windows-flavoured trivia.
// PROCESS_QUERY_LIMITED_INFORMATION does not cross user accounts, so a dpb
// running as SYSTEM — the service Plan 5 ships — or under another desktop user
// answers ERROR_ACCESS_DENIED to the liveness query. Reading that refusal as
// "dead" makes OwnerAlive false, PriorResidue true, and Replay revert a LIVE
// run's proxy, DNS and routes mid-session. The opposite mistake costs a stale
// lock file the user clears with one command, so the two are resolved
// differently on purpose.
func TestUnknownOwnerResolvesAsAlive(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    ownerVerdict
		want bool
	}{
		{"a query that concluded nothing", ownerUnknown, true},
		{"positive evidence of death", ownerGone, false},
		{"positive evidence of life", ownerPresent, true},
	} {
		if got := tc.v.alive(); got != tc.want {
			t.Errorf("%s: alive() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ownerUnknown is the zero value on purpose: a verdict nobody filled in is the
// conservative one, so a future leaf that forgets to classify an error path
// fails safe rather than tearing down a live run's networking.
func TestTheZeroVerdictIsTheSafeOne(t *testing.T) {
	var v ownerVerdict
	if v != ownerUnknown {
		t.Fatalf("the zero ownerVerdict is %d, want ownerUnknown (%d)", v, ownerUnknown)
	}
	if !v.alive() {
		t.Fatal("an unset verdict resolved as dead; a leaf that forgets to classify would revert a live run")
	}
}
