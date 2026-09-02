package resolve

import (
	"net/netip"
	"strings"
	"testing"
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

func TestUniformIgnoresMultiAddressAnswers(t *testing.T) {
	d := NewDetector([]netip.Addr{}, []string{"discord.com", "discord.gg", "cdn.discordapp.com"})
	// A real Cloudflare answer carries several addresses; learning from it
	// would poison the heuristic with legitimate shared infrastructure.
	for _, n := range []string{"discord.com", "discord.gg", "cdn.discordapp.com"} {
		d.Learn(n, genuineAnswer)
	}
	if sig := d.Check("discord.com", []netip.Addr{genuineAnswer[0]}); sig.Poisoned {
		t.Fatalf("multi-address answers must never feed the heuristic: %+v", sig)
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
	if len(d.singles) > uniformCap {
		t.Fatalf("learned map grew to %d, above the %d cap", len(d.singles), uniformCap)
	}
	if sig := d.Check("discord.com", nil); sig.Poisoned {
		t.Fatalf("an empty answer is not poison: %+v", sig)
	}
}
