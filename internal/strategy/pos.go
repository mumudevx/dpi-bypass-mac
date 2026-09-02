package strategy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// Anchor names the reference point a Pos is measured from.
type Anchor uint8

const (
	AnchorAbs Anchor = iota
	AnchorSNIStart
	AnchorSNIMid
	AnchorSNIEnd
	AnchorBodyMid
	AnchorHostStart
	AnchorHostEnd
)

var anchorNames = []struct {
	a Anchor
	n string
}{
	{AnchorSNIStart, "snistart"},
	{AnchorSNIMid, "snimid"},
	{AnchorSNIEnd, "sniend"},
	{AnchorBodyMid, "bodymid"},
	{AnchorHostStart, "hoststart"},
	{AnchorHostEnd, "hostend"},
}

func (a Anchor) String() string {
	for _, e := range anchorNames {
		if e.a == a {
			return e.n
		}
	}
	return "abs"
}

// maxPosDelta bounds a position so that Resolve can never overflow. The first
// message is capped at 64 KiB (DOSSIER §2), so a megabyte of slack is generous
// and still leaves int arithmetic nowhere near the edge.
const maxPosDelta = 1 << 20

// Pos is a cut position: either an absolute offset or an offset relative to a
// feature of the parsed first message.
//
// Which buffer the offset indexes depends on the anchor, because tlsmsg.Meta
// expresses the two families in different coordinate systems: the SNI and body
// anchors are relative to the FIRST TLS RECORD'S BODY (that is the coordinate
// system the measured rule is stated in), while the host anchors are absolute
// offsets into the HTTP payload.
type Pos struct {
	Anchor Anchor
	Delta  int
}

// ParsePos accepts an absolute non-negative integer ("12") or an anchor with an
// optional signed delta ("snimid", "sniend-1", "snistart+1", "hoststart-4").
func ParsePos(s string) (Pos, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return Pos{}, fmt.Errorf("%w: empty position", ErrBadValue)
	}
	if n, err := strconv.Atoi(t); err == nil {
		switch {
		case n < 0:
			return Pos{}, fmt.Errorf("%w: absolute position %q is negative", ErrBadValue, s)
		case n > maxPosDelta:
			return Pos{}, fmt.Errorf("%w: absolute position %q exceeds %d", ErrBadValue, s, maxPosDelta)
		}
		return Pos{Anchor: AnchorAbs, Delta: n}, nil
	}
	for _, e := range anchorNames {
		if !strings.HasPrefix(t, e.n) {
			continue
		}
		rest := t[len(e.n):]
		if rest == "" {
			return Pos{Anchor: e.a}, nil
		}
		if rest[0] != '+' && rest[0] != '-' {
			break // "snistartle" is not an anchor with a delta, it is a typo
		}
		d, err := strconv.Atoi(rest)
		if err != nil {
			return Pos{}, fmt.Errorf("%w: %q has anchor %s but %q is not a signed offset", ErrBadValue, s, e.n, rest)
		}
		if d > maxPosDelta || d < -maxPosDelta {
			return Pos{}, fmt.Errorf("%w: offset %q exceeds ±%d", ErrBadValue, rest, maxPosDelta)
		}
		return Pos{Anchor: e.a, Delta: d}, nil
	}
	return Pos{}, fmt.Errorf("%w: %q is not a position; want an integer or one of %s optionally followed by +N or -N",
		ErrBadValue, s, strings.Join(anchorList(), ", "))
}

func anchorList() []string {
	out := make([]string, 0, len(anchorNames))
	for _, e := range anchorNames {
		out = append(out, e.n)
	}
	return out
}

// String renders the canonical form. A zero delta is elided, so ParsePos
// round-trips and "snimid+0" and "snimid" are the same token.
func (p Pos) String() string {
	if p.Anchor == AnchorAbs {
		return strconv.Itoa(p.Delta)
	}
	switch {
	case p.Delta > 0:
		return p.Anchor.String() + "+" + strconv.Itoa(p.Delta)
	case p.Delta < 0:
		return p.Anchor.String() + strconv.Itoa(p.Delta)
	}
	return p.Anchor.String()
}

// Resolve maps the position onto a concrete offset. ok is false when the anchor
// has nothing to attach to — no SNI, no Host, no record body — or when the
// result would be negative. An unresolvable anchor must be an explicit failure:
// a silent zero here is a one-byte split, which MEASUREMENTS.md §3 measures at
// 0/5 while looking exactly like a working strategy in the logs.
func (p Pos) Resolve(m tlsmsg.Meta) (int, bool) {
	var base int
	switch p.Anchor {
	case AnchorAbs:
		base = 0
	case AnchorSNIStart:
		if !m.HasSNI() {
			return 0, false
		}
		base = m.SNIStart
	case AnchorSNIMid:
		if !m.HasSNI() {
			return 0, false
		}
		base = m.SNIStart + (m.SNIEnd-m.SNIStart)/2
	case AnchorSNIEnd:
		if !m.HasSNI() {
			return 0, false
		}
		base = m.SNIEnd
	case AnchorBodyMid:
		if m.BodyLen <= 0 {
			return 0, false
		}
		base = m.BodyLen / 2
	case AnchorHostStart:
		if !m.HasHost() {
			return 0, false
		}
		base = m.HostStart
	case AnchorHostEnd:
		if !m.HasHost() {
			return 0, false
		}
		base = m.HostEnd
	default:
		return 0, false
	}
	v := base + p.Delta
	if v < 0 {
		return 0, false
	}
	return v, true
}
