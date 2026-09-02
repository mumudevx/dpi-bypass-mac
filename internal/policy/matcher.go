package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// The matcher is security-relevant, and it is the one place the previous
// implementation got wrong in a way that mattered: it compared rules with a
// bare strings.HasSuffix, so a bypass for "bank.com" also fired on
// "evilbank.com" and a censored host could opt itself out of protection by
// choosing its name. Every comparison here is anchored on a label boundary,
// and FuzzMatchLabel pins that property.
//
// Three pattern forms, and no others — in particular no substring globbing:
//
//	bank.com     label-anchored: bank.com and any subdomain of it
//	.bank.com    the same thing; a spelling convenience, since exclusion lists
//	             in the wild write TLD-ish suffixes with a leading dot
//	*.bank.com   subdomains only; bank.com itself does NOT match
//	=bank.com    exact; subdomains do NOT match
type patternKind uint8

const (
	kindAnchored patternKind = iota
	kindWildcard
	kindExact
)

type entry struct {
	rule Rule
	kind patternKind
	base string // normalised, without the =, *. or leading-dot prefix
}

// Matcher resolves a hostname against a rule list. It is immutable once built,
// so it can be shared by every connection goroutine without a lock.
type Matcher struct {
	rules []Rule
	// byBase indexes entries by their normalised base name. Lookup walks the
	// host's label suffixes from longest to shortest, which yields matches in
	// most-specific-first order for free.
	byBase map[string][]entry
}

// NewMatcher compiles rules. It rejects a pattern that is really an address so
// a CIDR pasted into --bypass fails loudly instead of silently matching
// nothing; addresses belong in an IPSet.
func NewMatcher(rules []Rule) (*Matcher, error) {
	m := &Matcher{
		rules:  make([]Rule, 0, len(rules)),
		byBase: make(map[string][]entry, len(rules)),
	}
	for _, r := range rules {
		kind, base, err := parsePattern(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q from %s: %w", r.Pattern, r.Where(), err)
		}
		m.rules = append(m.rules, r)
		m.byBase[base] = append(m.byBase[base], entry{rule: r, kind: kind, base: base})
	}
	return m, nil
}

// Rules returns the compiled rules in input order.
func (m *Matcher) Rules() []Rule {
	if m == nil {
		return nil
	}
	return append([]Rule(nil), m.rules...)
}

// Len reports how many rules the matcher holds.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.rules)
}

// Match returns every rule matching host, most specific first. Ties within one
// base name keep input order, so an earlier line in a config file wins.
//
// A nil Matcher matches nothing, which is what makes "no rules configured" a
// zero-cost case on the connection path.
func (m *Matcher) Match(host string) []Rule {
	if m == nil || len(m.byBase) == 0 {
		return nil
	}
	name := Normalize(host)
	if name == "" {
		return nil
	}
	var out []Rule
	// Walk suffixes: the full name first, then after each dot. The first
	// iteration is the exact name; every later one is a proper parent domain,
	// which is precisely the label anchor.
	for i, exact := 0, true; i < len(name); exact = false {
		base := name[i:]
		for _, e := range m.byBase[base] {
			if e.matchesAt(exact) {
				out = append(out, e.rule)
			}
		}
		dot := strings.IndexByte(name[i:], '.')
		if dot < 0 {
			break
		}
		i += dot + 1
	}
	return out
}

func (e entry) matchesAt(exact bool) bool {
	switch e.kind {
	case kindExact:
		return exact
	case kindWildcard:
		return !exact
	default:
		return true
	}
}

// MatchLabel reports whether host is covered by pattern, anchored on a label
// boundary. It is the primitive Match is built from, exported because it is
// the property worth fuzzing on its own:
//
//	MatchLabel("bank.com", "bank.com")       == true
//	MatchLabel("bank.com", "www.bank.com")   == true
//	MatchLabel("bank.com", "evilbank.com")   == false
//	MatchLabel("bank.com", "bank.com.evil.tld") == false
func MatchLabel(pattern, host string) bool {
	kind, base, err := parsePattern(pattern)
	if err != nil {
		return false
	}
	name := Normalize(host)
	if name == "" || base == "" {
		return false
	}
	switch kind {
	case kindExact:
		return name == base
	case kindWildcard:
		return isSubdomain(name, base)
	default:
		return name == base || isSubdomain(name, base)
	}
}

// isSubdomain is the anchor. The len check keeps the slice bounds honest and
// the byte compare guarantees the character before the suffix is a real label
// separator, which is the whole difference between bank.com and evilbank.com.
func isSubdomain(name, base string) bool {
	if len(name) <= len(base)+1 {
		return false
	}
	if name[len(name)-len(base)-1] != '.' {
		return false
	}
	return name[len(name)-len(base):] == base
}

func parsePattern(p string) (patternKind, string, error) {
	s := strings.TrimSpace(p)
	if s == "" {
		return 0, "", fmt.Errorf("empty pattern")
	}
	kind := kindAnchored
	switch {
	case strings.HasPrefix(s, "="):
		kind, s = kindExact, s[1:]
	case strings.HasPrefix(s, "*."):
		kind, s = kindWildcard, s[2:]
	case strings.HasPrefix(s, "."):
		s = s[1:]
	}
	if strings.ContainsAny(s, "*?[]") {
		return 0, "", fmt.Errorf("wildcards are only allowed as a leading %q label", "*.")
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return 0, "", fmt.Errorf("looks like a CIDR; address rules belong in the IP set")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return 0, "", fmt.Errorf("looks like an IP address; address rules belong in the IP set")
	}
	base := Normalize(s)
	if base == "" {
		return 0, "", fmt.Errorf("not a usable hostname")
	}
	return kind, base, nil
}

const (
	maxNameLen  = 253
	maxLabelLen = 63
	// maxLabelRunes bounds the punycode encoder's input. A label can never
	// encode to a legal 63-byte A-label from more than this many runes, and
	// the bound is what keeps the delta arithmetic below far from overflow on
	// fuzzer-supplied input.
	maxLabelRunes = 256
	// maxInputLen bounds the work one lookup can cost. Normalize runs on the
	// connection path against values an attacker chooses — an SNI, a CONNECT
	// target, a SOCKS5 domain — and no hostname that normalises to 253 bytes
	// can come from more than this much UTF-8, since punycode output is never
	// shorter than the rune count it encodes. Rejecting early keeps a lookup
	// constant-cost instead of linear in whatever the peer sent.
	maxInputLen = 1024
)

// Normalize turns a hostname into the single canonical form every lookup, rule
// and cache key in this package uses: lower-case, no trailing root dot, no
// surrounding space, no brackets, and punycode rather than Unicode.
//
// Normalising through IDNA is not cosmetic. "bank.com" and "bɑnk.com" are
// different names but "BANK.com." and "bank.com" are the same one, and a
// matcher that misses that is a matcher an attacker steers with capital
// letters. An IP literal is returned in its canonical address form so the
// caller can re-parse it.
//
// It returns "" for anything that cannot be a hostname, and every caller
// treats "" as "matches nothing" — the safe direction, because an unmatched
// host gets the default ScopeWatch and is still sent plain first.
func Normalize(host string) string {
	if len(host) > maxInputLen {
		return ""
	}
	s := strings.TrimSpace(host)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return ""
	}
	// A bracketed IPv6 literal arrives from URLs and from net.SplitHostPort
	// callers that did not unwrap it.
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return canonAddr(addr).String()
	}
	// Validate before folding: strings.ToLower rewrites invalid bytes to
	// U+FFFD, which would launder mojibake into a legal-looking A-label and
	// give two different byte strings the same cache key.
	if !utf8.ValidString(s) {
		return ""
	}
	out, err := toASCII(strings.ToLower(s))
	if err != nil {
		return ""
	}
	if out == "" || len(out) > maxNameLen {
		return ""
	}
	// Whitelist the output alphabet rather than blacklisting delimiters. An
	// A-label is [a-z0-9-] by construction; "_" is added because real names
	// use it. Everything else — a stray colon from a host:port, a slash from a
	// URL, a control character, a Unicode space that survived trimming — makes
	// the name unusable, and rejecting it is what keeps Normalize idempotent.
	for i := 0; i < len(out); i++ {
		c := out[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return ""
		}
	}
	for _, label := range strings.Split(out, ".") {
		if label == "" || len(label) > maxLabelLen {
			return ""
		}
	}
	return out
}

// toASCII converts a lower-cased hostname to its A-label form, encoding any
// label that contains non-ASCII with punycode.
//
// This is a deliberately narrow slice of UTS #46: case folding (done by the
// caller) plus RFC 3492 encoding, with no NFC normalisation and no
// script/bidi validation, because golang.org/x/text is not a dependency of
// this project and adding one for a matcher is not a trade worth making. The
// consequence is bounded and documented: a rule written in a decomposed
// Unicode form will not match the composed spelling of the same name. Every
// ASCII rule — which is every rule dpb ships — is unaffected.
func toASCII(s string) (string, error) {
	if isASCII(s) {
		return s, nil
	}
	labels := strings.Split(s, ".")
	for i, l := range labels {
		if isASCII(l) {
			continue
		}
		enc, err := punyEncode(l)
		if err != nil {
			return "", err
		}
		labels[i] = enc
	}
	return strings.Join(labels, "."), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// RFC 3492 parameters.
const (
	punyBase        = 36
	punyTmin        = 1
	punyTmax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128
)

// punyEncode implements the RFC 3492 encoder for one label.
func punyEncode(label string) (string, error) {
	runes := []rune(label)
	if len(runes) > maxLabelRunes {
		return "", fmt.Errorf("label is too long to encode")
	}
	var out strings.Builder
	out.WriteString("xn--")
	basic := 0
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out.WriteByte(byte(r))
			basic++
		}
	}
	if basic > 0 {
		out.WriteByte('-')
	}

	n, delta, bias := punyInitialN, 0, punyInitialBias
	for h := basic; h < len(runes); {
		// m is the smallest code point at or above n that still needs
		// encoding.
		m := 0x7fffffff
		for _, r := range runes {
			if c := int(r); c >= n && c < m {
				m = c
			}
		}
		if m == 0x7fffffff {
			return "", fmt.Errorf("label cannot be encoded")
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			c := int(r)
			if c < n {
				delta++
			}
			if c != n {
				continue
			}
			q := delta
			for k := punyBase; ; k += punyBase {
				t := k - bias
				switch {
				case t < punyTmin:
					t = punyTmin
				case t > punyTmax:
					t = punyTmax
				}
				if q < t {
					break
				}
				out.WriteByte(punyDigit(t + (q-t)%(punyBase-t)))
				q = (q - t) / (punyBase - t)
			}
			out.WriteByte(punyDigit(q))
			bias = punyAdapt(delta, h+1, h == basic)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return out.String(), nil
}

func punyAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punyBase-punyTmin)*punyTmax)/2 {
		delta /= punyBase - punyTmin
		k += punyBase
	}
	return k + (punyBase-punyTmin+1)*delta/(delta+punySkew)
}

func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
