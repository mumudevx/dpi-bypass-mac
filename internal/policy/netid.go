package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
)

// NetworkID namespaces every learned verdict so a home-WiFi result is never
// replayed on a cellular hotspot with a different censor.
//
// This is not a nicety. MEASUREMENTS.md was taken on one Türk Telekom line;
// the same laptop on a mobile carrier, on a corporate LAN or behind a VPN
// meets a different middlebox, and replaying "discord.com needs tlsfrag" onto
// a network where plain works would desync a flow with no evidence at all —
// exactly what §5.2 forbids. Conversely, replaying "plain works" onto a
// censored network would silently stop bypassing.
type NetworkID struct {
	Kind        string // wifi | ethernet | cellular | vpn | unknown
	SSID        string
	Gateway     netip.Addr
	GatewayMAC  string
	ResolverSet string
}

// IsZero reports whether the identity carries no distinguishing fact at all.
// A zero NetworkID is still a valid namespace — it is the one used before the
// first fact collection completes — but a caller that wants to avoid writing
// verdicts under it can check.
func (n NetworkID) IsZero() bool {
	return n.Kind == "" && n.SSID == "" && !n.Gateway.IsValid() &&
		n.GatewayMAC == "" && n.ResolverSet == ""
}

// canonical renders the identity as the exact bytes Key hashes. Every field is
// normalised first so that cosmetic differences between two collections of the
// same network — an uppercase MAC, a 4-in-6 gateway — do not split the cache
// and lose a user their learned verdicts on every reconnect.
func (n NetworkID) canonical() string {
	kind := strings.ToLower(strings.TrimSpace(n.Kind))
	if kind == "" {
		kind = "unknown"
	}
	gw := ""
	if n.Gateway.IsValid() {
		gw = canonAddr(n.Gateway).String()
	}
	mac := strings.ToLower(strings.TrimSpace(n.GatewayMAC))
	var b strings.Builder
	b.WriteString("v1\x00")
	b.WriteString(kind)
	b.WriteByte(0)
	b.WriteString(strings.TrimSpace(n.SSID))
	b.WriteByte(0)
	b.WriteString(gw)
	b.WriteByte(0)
	b.WriteString(mac)
	b.WriteByte(0)
	b.WriteString(strings.TrimSpace(n.ResolverSet))
	return b.String()
}

// Key is the stable namespace string: a readable kind prefix plus a digest of
// every field.
//
// It is deterministic across runs and across machines — the store on disk is
// keyed by it, so a salt would throw away the cache on every restart — and it
// is a digest rather than the raw fields because the key appears in log lines
// and in `dpb status --json`, and an SSID is identifying. It is also
// filesystem- and JSON-safe by construction.
func (n NetworkID) Key() string {
	sum := sha256.Sum256([]byte(n.canonical()))
	kind := strings.ToLower(strings.TrimSpace(n.Kind))
	if kind == "" {
		kind = "unknown"
	}
	kind = sanitizeKind(kind)
	return kind + "-" + hex.EncodeToString(sum[:8])
}

// Equal reports whether two identities name the same network.
func (n NetworkID) Equal(o NetworkID) bool { return n.Key() == o.Key() }

// String is the Key; it is what belongs in a log line.
func (n NetworkID) String() string { return n.Key() }

// sanitizeKind keeps the readable half of the key to a fixed, safe alphabet so
// it can be a path segment without escaping.
func sanitizeKind(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 16 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// ResolverSetHash folds the system's configured resolvers into the single
// string NetworkID.ResolverSet expects.
//
// The resolver set is the most censorship-relevant fact about a network — on
// the measured line the ISP resolver answers 195.175.254.2 for every blocked
// name (MEASUREMENTS.md §2) — and it is the field that distinguishes two WiFi
// networks that happen to share a 192.168.0.1 gateway. Order and case are
// normalised away because macOS reports them inconsistently across reconnects.
func ResolverSetHash(addrs []string) string {
	seen := make(map[string]struct{}, len(addrs))
	norm := make([]string, 0, len(addrs))
	for _, a := range addrs {
		s := strings.ToLower(strings.TrimSpace(a))
		if s == "" {
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			s = canonAddr(addr).String()
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		norm = append(norm, s)
	}
	if len(norm) == 0 {
		return ""
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, ",")))
	return hex.EncodeToString(sum[:8])
}
