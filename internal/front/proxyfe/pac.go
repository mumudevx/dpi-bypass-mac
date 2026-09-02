package proxyfe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// PACPath is the URL path the auto-proxy configuration is served at.
const PACPath = "/dpb.pac"

// PAC generates the proxy auto-configuration macOS is pointed at.
//
// Two properties are load-bearing, and both are refusals:
//
//   - It never calls dnsResolve. A PAC that resolves the name to decide is a
//     PAC that hands every hostname the browser visits to the system resolver,
//     which on this line answers blocked names with the ISP sinkhole
//     (MEASUREMENTS.md §2). The matching here is pure string work on the host,
//     so the name never leaves the browser.
//   - It never returns "PROXY ...; DIRECT". The fallback looks like resilience
//     and is the opposite: if dpb is briefly unreachable, the browser silently
//     sends an unmodified ClientHello for a blocked name and the block simply
//     applies. Failing to connect is the honest outcome, and macOS already
//     gives us the fail-open story we want at the other end — an unfetchable
//     PAC URL is treated as DIRECT, so process death degrades to normal
//     browsing rather than to an outage.
type PAC struct {
	// Host and Port are the listener the browser is sent to.
	Host string
	Port int
	// Bypass are the patterns that resolve to DIRECT: names in policy's three
	// spellings (anchored, *.wildcard, =exact) and IPv4 CIDRs.
	Bypass []string
	// Suspended, when it returns true, makes the whole script return DIRECT.
	// That is the captive-portal suspend and the `dpb off` kill switch: the
	// system setting stays in place and valid, and every request goes straight
	// out, so nothing has to be re-applied when the portal clears.
	Suspended func() bool
}

// URL is the auto-proxy URL to point the system at.
func (p *PAC) URL() string {
	return "http://" + net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) + PACPath
}

// Script renders the PAC for the current suspend state.
func (p *PAC) Script() []byte {
	if p.Suspended != nil && p.Suspended() {
		return []byte(suspendedScript)
	}
	return p.script()
}

// Active renders the script that is served while dpb is doing its job. It is
// what is written to disk, so that the on-disk copy is the bytes a browser
// would fetch rather than a second rendering that could differ.
func (p *PAC) Active() []byte { return p.script() }

// SHA256 is the digest of the active script, for `dpb doctor` to compare the
// file on disk against what this build would generate.
func (p *PAC) SHA256() string {
	sum := sha256.Sum256(p.Active())
	return hex.EncodeToString(sum[:])
}

const suspendedScript = `// dpb: suspended. Every request goes DIRECT.
//
// The system proxy setting is deliberately left in place: taking it away and
// putting it back is two more system mutations, and this file returning DIRECT
// achieves the same thing with none.
function FindProxyForURL(url, host) { return "DIRECT"; }
`

// pacPatterns is the bypass list split into the four shapes the script tests.
type pacPatterns struct {
	anchored []string // host, or any subdomain of it
	wildcard []string // subdomains only
	exact    []string // this host and nothing else
	nets     []pacNet // IPv4 CIDRs
	skipped  []string // v6 CIDRs, which PAC has no portable predicate for
}

type pacNet struct{ base, mask string }

func splitPatterns(in []string) pacPatterns {
	var p pacPatterns
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			if pfx.Addr().Is4() {
				p.nets = append(p.nets, pacNet{base: pfx.Masked().Addr().String(), mask: v4Mask(pfx.Bits())})
			} else {
				p.skipped = append(p.skipped, s)
			}
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			if a.Is4() {
				p.nets = append(p.nets, pacNet{base: a.String(), mask: "255.255.255.255"})
			} else {
				p.skipped = append(p.skipped, s)
			}
			continue
		}
		switch {
		case strings.HasPrefix(s, "="):
			p.exact = append(p.exact, strings.TrimPrefix(s, "="))
		case strings.HasPrefix(s, "*."):
			p.wildcard = append(p.wildcard, strings.TrimPrefix(s, "*."))
		default:
			p.anchored = append(p.anchored, strings.TrimPrefix(s, "."))
		}
	}
	sort.Strings(p.anchored)
	sort.Strings(p.wildcard)
	sort.Strings(p.exact)
	sort.Strings(p.skipped)
	sort.Slice(p.nets, func(i, j int) bool {
		if p.nets[i].base != p.nets[j].base {
			return p.nets[i].base < p.nets[j].base
		}
		return p.nets[i].mask < p.nets[j].mask
	})
	return dedupe(p)
}

func dedupe(p pacPatterns) pacPatterns {
	p.anchored = uniq(p.anchored)
	p.wildcard = uniq(p.wildcard)
	p.exact = uniq(p.exact)
	p.skipped = uniq(p.skipped)
	nets := p.nets[:0]
	for i, n := range p.nets {
		if i > 0 && n == p.nets[i-1] {
			continue
		}
		nets = append(nets, n)
	}
	p.nets = nets
	return p
}

func uniq(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i > 0 && s == in[i-1] {
			continue
		}
		out = append(out, s)
	}
	return out
}

func v4Mask(bits int) string {
	m := net.CIDRMask(bits, 32)
	return net.IP(m).String()
}

func jsArray(in []string) string {
	q := make([]string, 0, len(in))
	for _, s := range in {
		q = append(q, strconv.Quote(s))
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func (p *PAC) script() []byte {
	pat := splitPatterns(p.Bypass)
	proxy := "PROXY " + net.JoinHostPort(p.Host, strconv.Itoa(p.Port))

	var b strings.Builder
	b.WriteString("// Generated by dpb. Do not edit: it is rewritten on every run.\n")
	b.WriteString("//\n")
	b.WriteString("// Matching is pure string work on the host. No name is resolved here:\n")
	b.WriteString("// resolving would hand every hostname to the system resolver, which answers\n")
	b.WriteString("// blocked names with the ISP sinkhole (MEASUREMENTS.md 2). And the proxy\n")
	b.WriteString("// result carries no second, unproxied alternative: falling back would send an\n")
	b.WriteString("// unmodified ClientHello for a blocked name the moment dpb hiccuped, which is\n")
	b.WriteString("// exactly the leak this tool exists to close.\n")
	for _, s := range pat.skipped {
		fmt.Fprintf(&b, "//\n// NOT ENFORCED HERE: %s. PAC has no portable IPv6 network predicate,\n"+
			"// so this entry is honoured by dpb itself and not by the browser's own routing.\n", s)
	}
	b.WriteString("\nvar dpbAnchored = " + jsArray(pat.anchored) + ";\n")
	b.WriteString("var dpbWildcard = " + jsArray(pat.wildcard) + ";\n")
	b.WriteString("var dpbExact = " + jsArray(pat.exact) + ";\n")
	b.WriteString(`
function dpbEndsWithLabel(host, base) {
  if (host === base) return true;
  var n = host.length - base.length - 1;
  return n > 0 && host.charAt(n) === "." && host.substring(n + 1) === base;
}

function FindProxyForURL(url, host) {
  host = ("" + host).toLowerCase();
  if (host.charAt(host.length - 1) === ".") host = host.substring(0, host.length - 1);
  if (host === "") return "DIRECT";

  // An unqualified name cannot be a censored public host, and sending it here
  // would break intranet resolution the browser does for itself.
  if (isPlainHostName(host)) return "DIRECT";

  var i;
  for (i = 0; i < dpbExact.length; i++) if (host === dpbExact[i]) return "DIRECT";
  for (i = 0; i < dpbAnchored.length; i++) if (dpbEndsWithLabel(host, dpbAnchored[i])) return "DIRECT";
  for (i = 0; i < dpbWildcard.length; i++) {
    var w = dpbWildcard[i];
    if (host !== w && dpbEndsWithLabel(host, w)) return "DIRECT";
  }

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
`)
	for _, n := range pat.nets {
		fmt.Fprintf(&b, "    if (isInNet(host, %q, %q)) return \"DIRECT\";\n", n.base, n.mask)
	}
	b.WriteString(`    if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
  }
  // An IPv6 literal other than loopback still goes through dpb: it carries no
  // name for this script to key on, but the ClientHello inside it does, and the
  // ladder judges that. GT19 records a BTK-registered IPv6 sinkhole, so sending
  // v6 straight out would be the one address family we never protect.
  if (host === "::1") return "DIRECT";

`)
	fmt.Fprintf(&b, "  return %q;\n}\n", proxy)
	return []byte(b.String())
}
