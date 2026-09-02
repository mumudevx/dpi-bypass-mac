package resolve

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// Signal is the verdict on one answer.
type Signal struct {
	Poisoned bool
	Sinkhole bool
	Uniform  bool
	Detail   string
}

// Detector judges whether an answer is censorship rather than DNS.
type Detector interface {
	Check(name string, addrs []netip.Addr) Signal
	Learn(name string, addrs []netip.Addr)
}

// DefaultSinkholes are the addresses this ISP hands back instead of an answer.
//
// 195.175.254.2 is measured first hand (MEASUREMENTS.md §2): the system
// resolver at 192.168.0.1 returns it for every blocked name while returning
// genuine answers for everything else, which makes it a reliable positive
// censorship signal rather than a heuristic. 2a01:358:4014:a00::3 is its IPv6
// counterpart, registered in RIPE with netname BTK (DOSSIER GT19).
var DefaultSinkholes = []netip.Addr{
	netip.MustParseAddr("195.175.254.2"),
	netip.MustParseAddr("2a01:358:4014:a00::3"),
}

// DefaultPoisonProbes are names measured blocked on Türk Telekom
// (MEASUREMENTS.md §1). They are the reference set for the uniqueness
// heuristic: it needs names that are known to be censored somewhere, not names
// that are known to be censored here.
var DefaultPoisonProbes = []string{"discord.com", "discord.gg", "cdn.discordapp.com"}

// uniformQuorum is how many distinct blocked names must collapse onto one
// address before the address is called a censor.
//
// Two is not enough. MEASUREMENTS.md §1 shows discord.com and cloudflare.com
// legitimately sharing 162.159.128.233, so any two Cloudflare-fronted names can
// coincide honestly. Three distinct blocked names each answering with a single
// identical address is the shape zapret's reference-free check looks for and is
// not something a real CDN produces for unrelated zones.
const uniformQuorum = 3

// uniformCap bounds the learned map. The heuristic needs a handful of probe
// names, not a history of the network.
const uniformCap = 256

// v6SinkholeBits is the prefix length applied to an IPv6 sentinel.
//
// A censor that answers from a /64 can move within it for free, and GT19
// registers the BTK block-page range as a block, not a host. Matching the
// containing /64 costs nothing: no legitimate answer for a user's traffic lives
// inside a block-page network.
const v6SinkholeBits = 64

type detector struct {
	mu      sync.Mutex
	sinks   []netip.Addr
	sinkNet []netip.Prefix
	probes  map[string]bool
	// singles maps an address to the set of distinct probe names that resolved
	// to it and to nothing else.
	singles map[netip.Addr]map[string]struct{}
}

// NewDetector seeds the sinkhole sentinels and the reference-free probe set.
//
// Passing nil sinkholes or nil probes selects the shipped defaults, so a
// caller that forgets to configure the detector still gets the measured
// 195.175.254.2 check rather than a detector that approves everything.
func NewDetector(sinkholes []netip.Addr, probes []string) Detector {
	if sinkholes == nil {
		sinkholes = DefaultSinkholes
	}
	if probes == nil {
		probes = DefaultPoisonProbes
	}
	d := &detector{
		probes:  make(map[string]bool, len(probes)),
		singles: make(map[netip.Addr]map[string]struct{}),
	}
	for _, a := range sinkholes {
		a = a.Unmap()
		if !a.IsValid() {
			continue
		}
		d.sinks = append(d.sinks, a)
		if a.Is6() {
			if p, err := a.Prefix(v6SinkholeBits); err == nil {
				d.sinkNet = append(d.sinkNet, p)
			}
		}
	}
	for _, n := range probes {
		if n = normName(n); n != "" {
			d.probes[n] = true
		}
	}
	return d
}

// normName lower-cases a name and drops the root label so a wire-format name
// ("discord.com.") and a configured name ("discord.com") compare equal.
func normName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".")
}

func (d *detector) isSinkhole(a netip.Addr) bool {
	a = a.Unmap()
	for _, s := range d.sinks {
		if s == a {
			return true
		}
	}
	for _, p := range d.sinkNet {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (d *detector) Check(name string, addrs []netip.Addr) Signal {
	name = normName(name)
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, a := range addrs {
		if d.isSinkhole(a) {
			return Signal{
				Poisoned: true,
				Sinkhole: true,
				Detail: fmt.Sprintf("%s answered %s, a known censorship sinkhole (MEASUREMENTS.md §2)",
					name, a),
			}
		}
	}

	// The uniqueness heuristic needs no ground truth about what is blocked
	// here: it only needs several names that are blocked *somewhere* to
	// collapse onto one address. That is a censor's answer, never a CDN's.
	if len(addrs) == 1 {
		a := addrs[0].Unmap()
		if set := d.singles[a]; len(set) >= uniformQuorum {
			return Signal{
				Poisoned: true,
				Uniform:  true,
				Detail: fmt.Sprintf("%s answered %s, which %d distinct blocked names also resolve to",
					name, a, len(set)),
			}
		}
	}
	return Signal{}
}

func (d *detector) Learn(name string, addrs []netip.Addr) {
	name = normName(name)
	// Only single-address answers count. A censor redirecting to a block page
	// has one address to give; a real CDN answer for a busy name does not.
	if len(addrs) != 1 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.probes[name] {
		return
	}
	a := addrs[0].Unmap()
	set := d.singles[a]
	if set == nil {
		if len(d.singles) >= uniformCap {
			return
		}
		set = make(map[string]struct{})
		d.singles[a] = set
	}
	set[name] = struct{}{}
}
