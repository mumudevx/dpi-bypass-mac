package resolve

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestSinkholeSentinelIsRejected pins MEASUREMENTS.md §2: the system resolver at
// 192.168.0.1 returns 195.175.254.2 for every blocked name and a genuine answer
// for everything else, which makes that address a reliable positive censorship
// signal rather than a guess.
func TestSinkholeSentinelIsRejected(t *testing.T) {
	d := NewDetector(nil, nil)
	sig := d.Check("discord.com", []netip.Addr{ttSinkhole})
	if !sig.Poisoned || !sig.Sinkhole {
		t.Fatalf("195.175.254.2 must be rejected, got %+v", sig)
	}
	if !strings.Contains(sig.Detail, "195.175.254.2") {
		t.Fatalf("detail must name the address, got %q", sig.Detail)
	}
	// The genuine answer §2 measured on the alternate port must pass.
	if sig := d.Check("discord.com", genuineAnswer); sig.Poisoned {
		t.Fatalf("the measured genuine answer must not be flagged: %+v", sig)
	}
}

// TestV6SinkholeMatchesTheBlock covers DOSSIER GT19: the BTK block-page address
// is registered as a network, so a censor moving within it must not escape the
// check.
func TestV6SinkholeMatchesTheBlock(t *testing.T) {
	d := NewDetector(nil, nil)
	inside := netip.MustParseAddr("2a01:358:4014:a00::99")
	if sig := d.Check("discord.com", []netip.Addr{inside}); !sig.Sinkhole {
		t.Fatalf("an address inside the sentinel /64 must be rejected, got %+v", sig)
	}
	outside := netip.MustParseAddr("2a01:358:4014:b00::3")
	if sig := d.Check("discord.com", []netip.Addr{outside}); sig.Poisoned {
		t.Fatalf("an address outside the /64 must pass, got %+v", sig)
	}
}

// TestUniformNeedsAQuorum is the guard against the obvious false positive:
// MEASUREMENTS.md §1 shows discord.com and cloudflare.com legitimately sharing
// 162.159.128.233, so two names collapsing onto one address is a CDN, not a
// censor.
func TestUniformNeedsAQuorum(t *testing.T) {
	shared := netip.MustParseAddr("10.10.10.10")
	d := NewDetector([]netip.Addr{}, []string{"discord.com", "discord.gg", "cdn.discordapp.com"})

	d.Learn("discord.com", []netip.Addr{shared})
	if sig := d.Check("discord.gg", []netip.Addr{shared}); sig.Poisoned {
		t.Fatalf("one prior name is not a quorum: %+v", sig)
	}
	d.Learn("discord.gg", []netip.Addr{shared})
	if sig := d.Check("cdn.discordapp.com", []netip.Addr{shared}); sig.Poisoned {
		t.Fatalf("two prior names is still a CDN-shaped coincidence: %+v", sig)
	}
	d.Learn("cdn.discordapp.com", []netip.Addr{shared})

	sig := d.Check("anything.example", []netip.Addr{shared})
	if !sig.Poisoned || !sig.Uniform {
		t.Fatalf("three distinct blocked names on one address is a censor: %+v", sig)
	}
	if !strings.Contains(sig.Detail, "10.10.10.10") {
		t.Fatalf("detail must name the address, got %q", sig.Detail)
	}
}

// TestUniformCatchesMultiAddressPoison is the fix for the guard this test used
// to encode backwards.
//
// It previously asserted that "multi-address answers must never feed the
// heuristic", which is what made the uniqueness defence inert: measured on the
// live line, all five shipped rungs answer every one of the three
// DefaultPoisonProbes with FIVE A records, so a len(addrs)==1 gate is never
// satisfied in normal operation and a censor injecting two block-page addresses
// is served as clean. The heuristic keys on the whole address set instead.
func TestUniformCatchesMultiAddressPoison(t *testing.T) {
	probes := []string{"discord.com", "discord.gg", "cdn.discordapp.com"}
	blockPage := []netip.Addr{
		netip.MustParseAddr("10.9.9.1"),
		netip.MustParseAddr("10.9.9.2"),
	}
	d := NewDetector([]netip.Addr{}, probes)
	for _, n := range probes {
		if sig := d.Check(n, blockPage); sig.Poisoned && n != probes[len(probes)-1] {
			t.Fatalf("%s: quorum reached too early: %+v", n, sig)
		}
		d.Learn(n, blockPage)
	}
	// Order is not part of the answer: every resolver here rotates its RRset,
	// so the reversed set must reach the same verdict.
	sig := d.Check("anything.example", []netip.Addr{blockPage[1], blockPage[0]})
	if !sig.Poisoned || !sig.Uniform {
		t.Fatalf("three distinct blocked names on one two-address set is a censor: %+v", sig)
	}
	if !sig.Addr.IsValid() {
		t.Fatalf("a uniform signal must name an address: %+v", sig)
	}
}

// TestUniformDoesNotFireOnRealCDNAnswers is the false positive the old
// single-address gate was defending against, held with the set-keyed heuristic.
//
// Measured on the live Türk Telekom line through both alternate-port rungs, the
// three probe names return three DIFFERENT five-address Cloudflare sets:
// discord.com -> 162.159.{128.233,135.232,136.232,137.232,138.232},
// discord.gg -> 162.159.{130,133,134,135,136}.234, and cdn.discordapp.com ->
// 162.159.{129,130,133,134,135}.233. Distinct sets can never reach one quorum.
func TestUniformDoesNotFireOnRealCDNAnswers(t *testing.T) {
	probes := []string{"discord.com", "discord.gg", "cdn.discordapp.com"}
	live := map[string][]netip.Addr{
		"discord.com": {
			netip.MustParseAddr("162.159.128.233"), netip.MustParseAddr("162.159.135.232"),
			netip.MustParseAddr("162.159.136.232"), netip.MustParseAddr("162.159.137.232"),
			netip.MustParseAddr("162.159.138.232"),
		},
		"discord.gg": {
			netip.MustParseAddr("162.159.130.234"), netip.MustParseAddr("162.159.133.234"),
			netip.MustParseAddr("162.159.134.234"), netip.MustParseAddr("162.159.135.234"),
			netip.MustParseAddr("162.159.136.234"),
		},
		"cdn.discordapp.com": {
			netip.MustParseAddr("162.159.129.233"), netip.MustParseAddr("162.159.130.233"),
			netip.MustParseAddr("162.159.133.233"), netip.MustParseAddr("162.159.134.233"),
			netip.MustParseAddr("162.159.135.233"),
		},
	}
	d := NewDetector([]netip.Addr{}, probes)
	for i := 0; i < 3; i++ {
		for _, n := range probes {
			if sig := d.Check(n, live[n]); sig.Poisoned {
				t.Fatalf("the measured live answer for %s must never be flagged: %+v", n, sig)
			}
			d.Learn(n, live[n])
		}
	}
	// A name outside the probe set is not evidence about anything.
	single := netip.MustParseAddr("10.0.0.1")
	for _, n := range []string{"a.example", "b.example", "c.example"} {
		d.Learn(n, []netip.Addr{single})
	}
	if sig := d.Check("d.example", []netip.Addr{single}); sig.Poisoned {
		t.Fatalf("names outside the probe set are not evidence: %+v", sig)
	}
}

// TestDetectorObservationsExpire pins the per-network lifetime: a captive
// portal that answers everything with one address must not follow the machine
// onto the next network.
func TestDetectorObservationsExpire(t *testing.T) {
	shared := netip.MustParseAddr("10.44.44.44")
	probes := []string{"discord.com", "discord.gg", "cdn.discordapp.com"}
	d := NewDetector([]netip.Addr{}, probes).(*detector)
	base := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := base
	d.now = func() time.Time { return clock }

	for _, n := range probes {
		d.Learn(n, []netip.Addr{shared})
	}
	if sig := d.Check("x.example", []netip.Addr{shared}); !sig.Uniform {
		t.Fatalf("quorum must be reached on the network it was observed on: %+v", sig)
	}
	clock = base.Add(answerSetTTL + time.Second)
	if sig := d.Check("x.example", []netip.Addr{shared}); sig.Poisoned {
		t.Fatalf("an observation older than %s must not condemn the next network: %+v", answerSetTTL, sig)
	}
}

func TestDetectorNormalisesWireNames(t *testing.T) {
	shared := netip.MustParseAddr("10.11.12.13")
	d := NewDetector([]netip.Addr{}, []string{"discord.com", "discord.gg", "cdn.discordapp.com"})
	// Wire-format names arrive fully qualified and mixed case.
	d.Learn("Discord.Com.", []netip.Addr{shared})
	d.Learn("DISCORD.GG.", []netip.Addr{shared})
	d.Learn("cdn.discordapp.com.", []netip.Addr{shared})
	if sig := d.Check("x.example.", []netip.Addr{shared}); !sig.Uniform {
		t.Fatalf("a wire-format name must match a configured one: %+v", sig)
	}
}

func TestDetectorCapAndInvalidInputs(t *testing.T) {
	d := NewDetector([]netip.Addr{{}, ttSinkhole}, []string{"", "  ", "discord.com"}).(*detector)
	if len(d.sinks) != 1 {
		t.Fatalf("invalid sentinels must be dropped, got %d", len(d.sinks))
	}
	if len(d.probes) != 1 {
		t.Fatalf("blank probe names must be dropped, got %d", len(d.probes))
	}
	// Fill past the cap and assert nothing grows without bound.
	for i := range uniformCap + 10 {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		d.Learn("discord.com", []netip.Addr{a})
	}
	if len(d.sets) > uniformCap {
		t.Fatalf("learned map grew to %d, above the %d cap", len(d.sets), uniformCap)
	}
	if sig := d.Check("discord.com", nil); sig.Poisoned {
		t.Fatalf("an empty answer is not poison: %+v", sig)
	}
}
