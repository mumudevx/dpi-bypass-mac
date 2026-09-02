package resolve

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Signal is the verdict on one answer.
type Signal struct {
	Poisoned bool
	Sinkhole bool
	Uniform  bool
	// Addr is the address the verdict is about: the one that matched a
	// sinkhole sentinel, or the lowest address of a set that reached the
	// uniqueness quorum. Callers must act on this address and no other —
	// re-scanning the answer for "an address that looks like the problem"
	// mis-attributes an IPv4 verdict to a legitimate IPv6 record that happened
	// to share the message.
	Addr   netip.Addr
	Detail string
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

// answerSetTTL bounds how long one observation of this network's answers is
// trusted.
//
// The learned map is a claim about the network the laptop is on, not about DNS
// in general. A captive portal or a hotel gateway that answers every name with
// one address reaches the quorum in three queries; without an expiry that
// observation follows the machine onto the next network and condemns a
// perfectly good answer there. Ten minutes matches nat64TTL, which bounds the
// other per-network determination for the same reason.
const answerSetTTL = 10 * time.Minute

// v6SinkholeBits is the prefix length applied to an IPv6 sentinel.
//
// A censor that answers from a /64 can move within it for free, and GT19
// registers the BTK block-page range as a block, not a host. Matching the
// containing /64 costs nothing: no legitimate answer for a user's traffic lives
// inside a block-page network.
const v6SinkholeBits = 64

// answerSet is the set of distinct probe names that returned one exact answer,
// and when that was last observed.
type answerSet struct {
	names map[string]struct{}
	seen  time.Time
}

type detector struct {
	mu      sync.Mutex
	sinks   []netip.Addr
	sinkNet []netip.Prefix
	probes  map[string]bool
	// sets maps a canonical answer — the full address set, sorted — to the
	// distinct probe names that resolved to exactly it.
	//
	// Keying on the whole set rather than requiring a single address is what
	// makes the heuristic reachable at all. Measured on the live Türk Telekom
	// line, every one of the five shipped rungs answers all three
	// DefaultPoisonProbes with FIVE A records, so a len(addrs)==1 guard is
	// never satisfied in normal operation and the uniqueness defence collapses
	// to the two literal DefaultSinkholes. A censor injecting two block-page
	// addresses would be served as clean.
	//
	// The CDN false positive the single-address guard was defending against
	// does not return: the quorum needs three distinct names on a byte-identical
	// set, and the same live measurement shows Cloudflare gives each zone its
	// own set (discord.com -> 162.159.{128.233,135.232,136.232,137.232,138.232},
	// discord.gg -> 162.159.{130,133,134,135,136}.234, cdn.discordapp.com ->
	// 162.159.{129,130,133,134,135}.233). Three unrelated zones landing on one
	// identical set is a censor's answer, not a CDN's.
	sets map[string]*answerSet
	now  func() time.Time
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
		probes: make(map[string]bool, len(probes)),
		sets:   make(map[string]*answerSet),
		now:    time.Now,
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

// answerKey canonicalises an answer's addresses into a comparable key. Order is
// not part of the answer — every resolver here rotates its RRset — so the
// addresses are sorted and de-duplicated first. An empty answer has no key: it
// carries no address to blame.
func answerKey(addrs []netip.Addr) (string, netip.Addr) {
	uniq := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		uniq = append(uniq, a)
	}
	if len(uniq) == 0 {
		return "", netip.Addr{}
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].Less(uniq[j]) })
	parts := make([]string, 0, len(uniq))
	for _, a := range uniq {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ","), uniq[0]
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
				Addr:     a.Unmap(),
				Detail: fmt.Sprintf("%s answered %s, a known censorship sinkhole (MEASUREMENTS.md §2)",
					name, a.Unmap()),
			}
		}
	}

	// The uniqueness heuristic needs no ground truth about what is blocked
	// here: it only needs several names that are blocked *somewhere* to
	// collapse onto one answer. That is a censor's reply, never a CDN's.
	d.expireLocked()
	key, first := answerKey(addrs)
	if key == "" {
		return Signal{}
	}
	if e := d.sets[key]; e != nil && len(e.names) >= uniformQuorum {
		return Signal{
			Poisoned: true,
			Uniform:  true,
			Addr:     first,
			Detail: fmt.Sprintf("%s answered %s, which %d distinct blocked names also resolve to",
				name, key, len(e.names)),
		}
	}
	return Signal{}
}

func (d *detector) Learn(name string, addrs []netip.Addr) {
	name = normName(name)
	key, _ := answerKey(addrs)
	if key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.probes[name] {
		return
	}
	d.expireLocked()
	e := d.sets[key]
	if e == nil {
		if len(d.sets) >= uniformCap {
			return
		}
		e = &answerSet{names: make(map[string]struct{})}
		d.sets[key] = e
	}
	e.names[name] = struct{}{}
	e.seen = d.now()
}

// expireLocked drops observations older than answerSetTTL.
func (d *detector) expireLocked() {
	now := d.now()
	for k, e := range d.sets {
		if now.Sub(e.seen) > answerSetTTL {
			delete(d.sets, k)
		}
	}
}
