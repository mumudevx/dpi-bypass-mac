package cliapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/resolve"
)

// The helpers below sit between the running process and what `dpb status`,
// `dpb why`, `dpb on` and `dpb off` print. runwiring_test.go drives them end to
// end over the control socket; these pin the invariants that an end-to-end test
// cannot see — which field went where, and whether a caller was handed the
// process's own slice.

// TestKillSwitchReportsWhyItIsOff: `dpb status` prints the reason beside the
// flag, so a kill switch that remembers the flag and forgets the reason leaves
// the user looking at a suspended proxy with no account of who suspended it.
func TestKillSwitchReportsWhyItIsOff(t *testing.T) {
	t.Parallel()
	var k killSwitch

	if off, reason := k.state(); off || reason != "" {
		t.Fatalf("the zero value is not on: off=%v reason=%q", off, reason)
	}
	if k.suspended() {
		t.Fatal("the zero value reports suspended")
	}

	k.set(true, "`dpb off`")
	off, reason := k.state()
	if !off || reason != "`dpb off`" {
		t.Fatalf("state after off = (%v, %q)", off, reason)
	}
	if !k.suspended() {
		t.Fatal("suspended() disagrees with state()")
	}

	k.set(false, "")
	if off, reason := k.state(); off || reason != "" {
		t.Fatalf("state after on = (%v, %q); a stale reason outlives the suspension", off, reason)
	}
}

// TestConnSummariesCarryEveryFieldWhyRenders: observ and policy sit on opposite
// sides of the import graph and this is the one place they meet, so a field
// dropped here is a field `dpb why` silently stops showing.
func TestConnSummariesCarryEveryFieldWhyRenders(t *testing.T) {
	t.Parallel()
	if got := connSummaries(nil); got != nil {
		t.Errorf("connSummaries(nil) = %+v, want nil", got)
	}
	at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	got := connSummaries([]observ.ConnStat{
		{At: at, Spec: "tlsfrag:pos=snimid", Attempts: 2, OK: true, Latency: 42 * time.Millisecond},
		{At: at.Add(time.Second), Spec: "", Attempts: 1, OK: false},
	})
	if len(got) != 2 {
		t.Fatalf("connSummaries returned %d rows, want 2", len(got))
	}
	want := policy.ConnSummary{
		At: at, Spec: "tlsfrag:pos=snimid", Attempts: 2, OK: true, Latency: 42 * time.Millisecond,
	}
	if got[0] != want {
		t.Errorf("connSummaries[0] = %+v, want %+v", got[0], want)
	}
	if got[1].OK || got[1].Spec != "" || got[1].Attempts != 1 {
		t.Errorf("connSummaries[1] = %+v", got[1])
	}
}

// TestResolverHealthKeepsUntriedApartFromBroken: a rung the chain never reached
// reports OK=false with a nil error, and flattening that onto the wire as
// "broken" invents a network problem the user does not have. `dpb status`
// renders Tried, so the distinction has to survive this conversion.
func TestResolverHealthKeepsUntriedApartFromBroken(t *testing.T) {
	t.Parallel()
	if got := resolverHealth(nil); got != nil {
		t.Errorf("resolverHealth(nil) = %+v, want nil", got)
	}
	rows := resolverHealth([]resolve.Health{
		{Label: "doh-cloudflare", OK: true, Latency: 26 * time.Millisecond},
		{Label: "udp-8.8.8.8-53", Err: errors.New("i/o timeout")},
		{Label: "udp-isp", Signal: resolve.Signal{Poisoned: true, Sinkhole: true}},
		{Label: "dot-9.9.9.9"},
	})
	if len(rows) != 4 {
		t.Fatalf("resolverHealth returned %d rows, want 4", len(rows))
	}
	if !rows[0].OK || !rows[0].Tried || rows[0].Err != "" {
		t.Errorf("a working rung = %+v", rows[0])
	}
	if rows[1].OK || !rows[1].Tried || rows[1].Err != "i/o timeout" {
		t.Errorf("a broken rung = %+v", rows[1])
	}
	if !rows[2].Sinkhole {
		t.Errorf("the sinkhole verdict was dropped: %+v", rows[2])
	}
	if rows[3].Tried {
		t.Errorf("an untried rung reports as tried: %+v", rows[3])
	}
}

// TestSystemReportCopiesWhatItReturns: the caller renders these slices while
// the run keeps mutating them, so handing out the live backing array is a data
// race with a status report on the other end of it.
func TestSystemReportCopiesWhatItReturns(t *testing.T) {
	t.Parallel()
	l := &liveState{}
	l.applied = []string{"web proxy on Wi-Fi"}
	l.setNotes([]string{"note"})

	applied, notes := l.systemReport()
	applied[0] = "mutated"
	notes[0] = "mutated"

	applied2, notes2 := l.systemReport()
	if applied2[0] == "mutated" || notes2[0] == "mutated" {
		t.Errorf("systemReport handed out its own slices: %v %v", applied2, notes2)
	}
}

// TestReloadSaysSoWhenItCannot: a dpb that cannot reload must answer with an
// error rather than a silent success, or `dpb reload` reports that a config it
// never re-read has been applied.
func TestReloadSaysSoWhenItCannot(t *testing.T) {
	t.Parallel()
	l := &liveState{}

	if err := l.doReload(context.Background()); err == nil {
		t.Fatal("doReload with no reload closure returned nil")
	}
	want := errors.New("bad config")
	l.reload = func(context.Context) error { return want }
	if err := l.doReload(context.Background()); !errors.Is(err, want) {
		t.Fatalf("doReload = %v, want %v", err, want)
	}
}
