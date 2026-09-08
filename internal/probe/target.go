// Package probe measures a censored line: it dials a real destination with a
// chosen strategy through the exact datapath the product uses, completes a real
// TLS handshake, and reports a verdict.
//
// It is deliberately not a second implementation of anything. A trial resolves
// through the same resolve.Chain, dials through the same flow.Dialer, compiles
// the same strategy.Strategy into the same strategy.Plan, and emits it through
// the same emit.Sender over the same emit.Transport as a proxied connection. A
// prober that measures a parallel implementation measures the wrong program.
package probe

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/mumudevx/dpb/internal/flow"
)

// TargetKind is what a target is being probed for.
type TargetKind uint8

const (
	// TargetBlocked is expected blocked; the thing a candidate must fix.
	TargetBlocked TargetKind = iota
	// TargetControl is expected reachable; it distinguishes "the strategy
	// failed" from "the network is down". It is interleaved in EVERY round, not
	// run once up front.
	TargetControl
	// TargetFragile is known to break under aggressive emitters. It is scored as
	// a COMPATIBILITY axis feeding ranking — never as a hard disqualifier,
	// because MEASUREMENTS.md §5.1 shows no emitter is both a bypass and
	// universally safe, so disqualification would zero out every candidate.
	TargetFragile
)

var targetKindNames = [...]string{"blocked", "control", "fragile"}

func (k TargetKind) String() string {
	if int(k) >= len(targetKindNames) {
		return "invalid"
	}
	return targetKindNames[k]
}

// DefaultPort is the port a target is probed on when none is given. The
// measured block (MEASUREMENTS.md §1) is SNI-keyed on 443.
const DefaultPort = 443

// Target is one destination of one trial.
type Target struct {
	Host string
	Port int
	Kind TargetKind
	// Addr pins the destination so a probe never resolves through the system
	// resolver. MEASUREMENTS.md §5.4: the first run of the compatibility matrix
	// scored every emitter 0/6 because Go's resolver returned the BTK sinkhole
	// 195.175.254.2, so every emitter was measured against a blackhole rather
	// than against the origin.
	//
	// It is a bare IP, without a port: the port is Port. An empty Addr means
	// "resolve through the tool's own chain", which is the only other way a name
	// may become an address.
	Addr string
}

// DialPort is the port to connect to.
func (t Target) DialPort() int {
	if t.Port > 0 {
		return t.Port
	}
	return DefaultPort
}

// Pinned returns the pinned address, if the target has one.
func (t Target) Pinned() (netip.Addr, bool) {
	if t.Addr == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(t.Addr)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Validate reports why the target cannot be probed, or nil.
func (t Target) Validate() error {
	if t.Host == "" {
		return fmt.Errorf("probe: target has no host")
	}
	// Port 0 means DefaultPort. Anything else out of range is rejected here
	// rather than being quietly rounded up to 443 by DialPort: a probe that
	// silently measures a different port than the one asked for is a lie.
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("probe: target %q: port %d is out of range", t.Host, t.Port)
	}
	if t.Addr != "" {
		if _, err := netip.ParseAddr(t.Addr); err != nil {
			return fmt.Errorf("probe: target %q: pinned address %q is not an IP: %w", t.Host, t.Addr, err)
		}
	}
	return nil
}

// Flow is the dial target. Host is always carried through even when Addr is
// pinned, because the hostname is what the strategy layer keys on and what the
// TLS SNI must say — pinning changes where we connect, never what we claim to
// be talking to. That separation is the whole point of MEASUREMENTS.md §1's
// experiment: same IP, same port, only the SNI differs.
func (t Target) Flow() flow.Target {
	ft := flow.Target{Name: t.Host, Port: t.DialPort()}
	if a, ok := t.Pinned(); ok {
		ft.Addr = netip.AddrPortFrom(a, uint16(t.DialPort()))
	}
	return ft
}

// String renders the target the way a report line wants it.
func (t Target) String() string {
	hp := net.JoinHostPort(t.Host, strconv.Itoa(t.DialPort()))
	if t.Addr == "" {
		return hp
	}
	return hp + "[" + t.Addr + "]"
}
