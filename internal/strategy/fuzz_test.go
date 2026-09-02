package strategy

import (
	"bytes"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// A spec is a wire format: the prober serialises it, the verdict store caches
// it under a NetworkID, `dpb tune --export` prints it for someone to paste into
// a forum, and `dpb apply` reads it back. If Parse(String(Parse(s))) drifted
// from Parse(s), every one of those would silently disagree with the strategy
// that was actually measured.
func FuzzSpecRoundTrip(f *testing.F) {
	seeds := []string{
		"", "plain", "plain|plain",
		"tlsfrag:pos=snimid",
		"tlsfrag:pos=sniend-1",
		"tlsfrag:pos=snistart-20",
		"chunk:size=12", "chunk:size=012", "chunk:size=+12",
		"oob:pos=1,junk=1", "oob:junk=2,pos=3",
		"quicfake:count=2,ttl=4",
		"hostcase|hostdot|chunk:size=12",
		"chunk:size=12|hostcase",
		"tlsfrag:pos=snimid|chunk:size=12",
		"hostpad:len=1", "hostpad:len=8",
		" tlsfrag : pos = snimid ",
		"tlsfrag:pos=snimid|tlsevery:period=64",
		"disorder:pos=1|oob:pos=1",
		"seqovl:pos=4",
		"nosuchop", "chunk:", "chunk:size", "|", "chunk:size=12,,",
	}
	for _, name := range LadderNames() {
		specs, _ := LadderSpecs(name)
		seeds = append(seeds, specs...)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, spec string) {
		first, err := Parse(spec)
		if err != nil {
			// A rejected spec must stay rejected: an error that depended on
			// anything but the input would make failures unreproducible.
			if _, again := Parse(spec); again == nil {
				t.Fatalf("Parse(%q) failed then succeeded", spec)
			}
			return
		}
		canon := first.String()

		second, err := Parse(canon)
		if err != nil {
			t.Fatalf("Parse(%q) ok but the canonical form %q does not parse: %v", spec, canon, err)
		}
		if got := second.String(); got != canon {
			t.Fatalf("canonicalisation is not idempotent: %q -> %q -> %q", spec, canon, got)
		}

		// The value must round-trip, not just the text.
		if len(second.Steps) != len(first.Steps) {
			t.Fatalf("%q: %d steps, re-parsed to %d", spec, len(first.Steps), len(second.Steps))
		}
		for i := range first.Steps {
			if first.Steps[i].Name() != second.Steps[i].Name() {
				t.Fatalf("%q: step %d is %q, re-parsed to %q", spec, i, first.Steps[i].Name(), second.Steps[i].Name())
			}
			if first.Steps[i].Caps() != second.Steps[i].Caps() {
				t.Fatalf("%q: step %d caps drifted", spec, i)
			}
		}
		if first.Caps() != second.Caps() ||
			first.Requires() != second.Requires() ||
			first.Determinism() != second.Determinism() ||
			first.IsPlain() != second.IsPlain() {
			t.Fatalf("%q: strategy properties changed across a round trip", spec)
		}
	})
}

func FuzzParsePos(f *testing.F) {
	for _, s := range []string{
		"0", "12", "012", "+12", "-1", "snistart", "snistart-20", "snistart+1",
		"snimid", "sniend", "sniend-1", "bodymid", "hoststart", "hostend", "sni", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePos(s)
		if err != nil {
			return
		}
		text := p.String()
		again, err := ParsePos(text)
		if err != nil {
			t.Fatalf("ParsePos(%q) = %+v but its own String() %q does not parse: %v", s, p, text, err)
		}
		if again != p {
			t.Fatalf("ParsePos(%q) = %+v, round-tripped to %+v", s, p, again)
		}
		if again.String() != text {
			t.Fatalf("Pos.String is not idempotent: %q -> %q", text, again.String())
		}
	})
}

// The categorical invariant: whatever a strategy does, the bytes the peer's TCP
// reassembles are exactly the bytes the plan declares. A bypass tool that
// corrupts a stream is worse than no tool.
func FuzzPlanPreservesPayload(f *testing.F) {
	hello := realHello("discord.com")
	f.Add(hello, "tlsfrag:pos=snimid")
	f.Add(hello, "tlsfrag:pos=sniend-1")
	f.Add(hello, "chunk:size=12")
	f.Add(hello, "tlsfrag:pos=snimid|chunk:size=120")
	f.Add(hello, "oob:pos=1")
	f.Add([]byte("GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n"), "hostcase|hostdot|chunk:size=8")
	f.Add([]byte{}, "")

	f.Fuzz(func(t *testing.T, payload []byte, spec string) {
		if len(payload) > 8192 {
			return
		}
		s, err := Parse(spec)
		if err != nil {
			return
		}
		m := tlsmsg.Parse(payload, 443)
		p, err := s.Build(payload, m, allCaps, DefaultBudget())
		if err != nil {
			return
		}
		if !bytes.Equal(p.StreamBytes(), p.Payload) {
			t.Fatalf("spec %q corrupted the stream: %d stream bytes vs %d payload bytes",
				spec, len(p.StreamBytes()), len(p.Payload))
		}
		if p.WriteCount() > DefaultBudget().MaxSegments {
			t.Fatalf("spec %q produced %d writes, over the budget", spec, p.WriteCount())
		}
		// Validate is the same gate Build already ran; re-running it here means
		// a future Build that forgets to call it fails this fuzzer.
		if err := p.Validate(DefaultBudget()); err != nil {
			t.Fatalf("spec %q built an invalid plan: %v", spec, err)
		}
	})
}
