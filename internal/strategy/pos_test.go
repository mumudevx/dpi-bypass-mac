package strategy

import (
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/tlsmsg"
)

func TestParsePosRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  Pos
		canon string
	}{
		{"12", Pos{AnchorAbs, 12}, "12"},
		{"0", Pos{AnchorAbs, 0}, "0"},
		{"+12", Pos{AnchorAbs, 12}, "12"},  // canonicalised
		{"012", Pos{AnchorAbs, 12}, "12"},  // canonicalised
		{" 12 ", Pos{AnchorAbs, 12}, "12"}, // canonicalised
		{"snistart", Pos{AnchorSNIStart, 0}, "snistart"},
		{"snistart-20", Pos{AnchorSNIStart, -20}, "snistart-20"},
		{"snistart+1", Pos{AnchorSNIStart, 1}, "snistart+1"},
		{"snistart+0", Pos{AnchorSNIStart, 0}, "snistart"}, // canonicalised
		{"snistart-0", Pos{AnchorSNIStart, 0}, "snistart"}, // canonicalised
		{"snimid", Pos{AnchorSNIMid, 0}, "snimid"},
		{"sniend", Pos{AnchorSNIEnd, 0}, "sniend"},
		{"sniend-1", Pos{AnchorSNIEnd, -1}, "sniend-1"},
		{"bodymid", Pos{AnchorBodyMid, 0}, "bodymid"},
		{"bodymid+8", Pos{AnchorBodyMid, 8}, "bodymid+8"},
		{"hoststart", Pos{AnchorHostStart, 0}, "hoststart"},
		{"hoststart-4", Pos{AnchorHostStart, -4}, "hoststart-4"},
		{"hostend", Pos{AnchorHostEnd, 0}, "hostend"},
	} {
		got, err := ParsePos(tc.in)
		if err != nil {
			t.Errorf("ParsePos(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParsePos(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
		if s := got.String(); s != tc.canon {
			t.Errorf("ParsePos(%q).String() = %q, want %q", tc.in, s, tc.canon)
		}
		// The property the prober depends on: a serialised position parses back
		// to the same value, and re-serialising changes nothing.
		again, err := ParsePos(got.String())
		if err != nil || again != got {
			t.Errorf("round trip of %q: %+v, %v", tc.in, again, err)
		}
	}
}

func TestParsePosRejects(t *testing.T) {
	for _, in := range []string{
		"", "   ", "-5", "sni", "snistartle", "snimid*3", "snimid 3",
		"snistart++1", "hoststart-", "12abc", "0x10", "99999999999999999999",
		"snimid+99999999", "snimid-2000000", "2000000",
	} {
		if p, err := ParsePos(in); err == nil {
			t.Errorf("ParsePos(%q) = %+v, want an error", in, p)
		} else if !errors.Is(err, ErrBadValue) {
			t.Errorf("ParsePos(%q): %v, want ErrBadValue", in, err)
		}
	}
}

func TestParsePosErrorNamesTheToken(t *testing.T) {
	_, err := ParsePos("snimad")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), `"snimad"`) {
		t.Errorf("error must quote the offending token: %v", err)
	}
	for _, a := range []string{"snistart", "snimid", "sniend", "bodymid", "hoststart", "hostend"} {
		if !strings.Contains(err.Error(), a) {
			t.Errorf("error must list the valid anchor %q: %v", a, err)
		}
	}
}

// The anchors resolve against MEASUREMENTS.md §3.2's geometry: a 1497-byte
// record body with the SNI hostname at [112,122).
func TestPosResolveAgainstMeasuredGeometry(t *testing.T) {
	_, m := measuredFixture()
	for _, tc := range []struct {
		spec string
		want int
	}{
		{"0", 0},
		{"92", 92},
		{"snistart", 112},
		{"snistart-20", 92},
		{"snistart-1", 111},
		{"snistart+1", 113},
		{"snimid", 117},
		{"sniend", 122},
		{"sniend-1", 121},
		{"bodymid", 748},
	} {
		p, err := ParsePos(tc.spec)
		if err != nil {
			t.Fatalf("ParsePos(%q): %v", tc.spec, err)
		}
		got, ok := p.Resolve(m)
		if !ok {
			t.Errorf("Resolve(%q) not ok", tc.spec)
			continue
		}
		if got != tc.want {
			t.Errorf("Resolve(%q) = %d, want %d", tc.spec, got, tc.want)
		}
	}
}

func TestPosResolveRefusesUnresolvable(t *testing.T) {
	noSNI := tlsmsg.Meta{Proto: tlsmsg.ProtoTLS, SNIStart: -1, SNIEnd: -1, HostStart: -1, HostEnd: -1}
	for _, spec := range []string{"snistart", "snimid", "sniend", "bodymid", "hoststart", "hostend"} {
		p, err := ParsePos(spec)
		if err != nil {
			t.Fatal(err)
		}
		// A silent zero here would degrade a record split into a one-byte TCP
		// split, which MEASUREMENTS.md §3 measures at 0/5 while still looking
		// like a working strategy in the logs.
		if got, ok := p.Resolve(noSNI); ok {
			t.Errorf("Resolve(%q) on a message with no SNI returned %d, want not-ok", spec, got)
		}
	}
	if _, ok := (Pos{Anchor: Anchor(99)}).Resolve(noSNI); ok {
		t.Error("an unknown anchor must not resolve")
	}
}

func TestPosResolveRefusesNegativeResult(t *testing.T) {
	_, m := measuredFixture()
	p := Pos{Anchor: AnchorSNIStart, Delta: -1000}
	if got, ok := p.Resolve(m); ok {
		t.Fatalf("Resolve = %d, want not-ok: a negative offset is not a position", got)
	}
}

func TestPosResolveHTTPAnchors(t *testing.T) {
	payload, m := httpFixture("example.com")
	if !m.HasHost() {
		t.Fatalf("fixture has no Host header: %q", payload)
	}
	for _, tc := range []struct {
		spec string
		want int
	}{
		{"hoststart", m.HostStart},
		{"hostend", m.HostEnd},
		{"hoststart-6", m.HostStart - 6},
	} {
		p, err := ParsePos(tc.spec)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := p.Resolve(m)
		if !ok || got != tc.want {
			t.Errorf("Resolve(%q) = %d,%v want %d,true", tc.spec, got, ok, tc.want)
		}
	}
}

func TestAnchorString(t *testing.T) {
	if got := AnchorAbs.String(); got != "abs" {
		t.Errorf("AnchorAbs = %q", got)
	}
	if got := AnchorHostEnd.String(); got != "hostend" {
		t.Errorf("AnchorHostEnd = %q", got)
	}
	if got := Anchor(200).String(); got != "abs" {
		t.Errorf("unknown anchor = %q, want the abs fallback", got)
	}
}
