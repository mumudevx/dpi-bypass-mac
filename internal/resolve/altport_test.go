package resolve

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// TestDefaultAltPortsAreTheMeasuredOnes pins MEASUREMENTS.md §2 verbatim:
// `dig -p 1253 @77.88.8.8 discord.com` and `dig -p 9953 @9.9.9.9 discord.com`
// both answered while port 53 for the same names timed out. These are not
// arbitrary ports; changing them without a new measurement changes the tool's
// only working plaintext transport.
func TestDefaultAltPortsAreTheMeasuredOnes(t *testing.T) {
	got := DefaultAltPorts()
	want := []string{"77.88.8.8:1253", "9.9.9.9:9953"}
	if len(got) != len(want) {
		t.Fatalf("got %d alt ports, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Addr != want[i] {
			t.Fatalf("alt port %d = %q, want the measured %q", i, got[i].Addr, want[i])
		}
	}
	rs, err := NewAltPortResolvers(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Transport() != "udp-alt" {
			t.Fatalf("%s transport = %q, want udp-alt", r.Label(), r.Transport())
		}
	}
}

func TestRankOrdersByLiveness(t *testing.T) {
	control := netip.MustParseAddr("142.250.187.174")
	slow := answering(t, "slow", "udp-alt", control)
	slow.delay = 120 * time.Millisecond
	fast := answering(t, "fast", "udp-alt", control)
	dead := &fakeResolver{label: "dead", transport: "udp-alt", t: t, delay: rankTimeout + time.Second}
	empty := rcodeRung(t, "empty", 0) // NOERROR with no answer is not liveness

	got := Rank(context.Background(), []Resolver{slow, dead, fast, empty}, "google.com", nil)
	if len(got) != 4 {
		t.Fatalf("Rank dropped resolvers: %v", got)
	}
	if got[0].Label() != "fast" || got[1].Label() != "slow" {
		t.Fatalf("live resolvers must lead, fastest first, got %s %s", got[0].Label(), got[1].Label())
	}
	// A dead resolver is ranked last, never removed: a slow resolver still
	// beats the sinkhole.
	if got[2].Label() != "dead" && got[3].Label() != "dead" {
		t.Fatalf("the dead resolver must survive the ranking: %v", got)
	}
}

func TestRankIsStableForTies(t *testing.T) {
	dead1 := &fakeResolver{label: "a", transport: "udp-alt", t: t}
	dead2 := &fakeResolver{label: "b", transport: "udp-alt", t: t}
	dead3 := &fakeResolver{label: "c", transport: "udp-alt", t: t}
	got := Rank(context.Background(), []Resolver{dead1, dead2, dead3}, "google.com", nil)
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Label() != want {
			t.Fatalf("equal results must keep the configured order, got %s at %d", got[i].Label(), i)
		}
	}
}

func TestRankShortCircuits(t *testing.T) {
	one := answering(t, "one", "udp-alt", netip.MustParseAddr("1.2.3.4"))
	if got := Rank(context.Background(), []Resolver{one}, "google.com", nil); len(got) != 1 {
		t.Fatalf("a single resolver needs no probe, got %v", got)
	}
	if one.Calls() != 0 {
		t.Fatalf("a single-resolver chain must not be probed, calls = %d", one.Calls())
	}
	// A control name that cannot be encoded must not silently reorder anything.
	two := answering(t, "two", "udp-alt", netip.MustParseAddr("1.2.3.4"))
	got := Rank(context.Background(), []Resolver{one, two}, "  ", func(string, ...any) {})
	if len(got) != 2 || got[0].Label() != "one" {
		t.Fatalf("a bad control must leave the configured order alone, got %v", got)
	}
}

func TestErrNoCleanTransportExists(t *testing.T) {
	// No packet strategy fixes a poisoned resolver, so the preflight needs a
	// distinguishable "stop here" error rather than a generic failure.
	if ErrNoCleanTransport == nil || ErrNoCleanTransport.Error() == "" {
		t.Fatal("ErrNoCleanTransport must carry a message")
	}
}
