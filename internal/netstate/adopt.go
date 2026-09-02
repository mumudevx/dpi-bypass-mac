package netstate

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// This file holds the two guards that make restoration honest.
//
// Adopted: Manager runs an Op's Verify before its Apply. If the state is
// already there, we did not create it, so the record is marked Adopted and
// Revert becomes a no-op. That is implemented in Manager.Do; what lives here is
// the second guard.
//
// notSelf: when an Op captures the previous value it will later restore, that
// value may already point at us — the residue of a run that was SIGKILLed
// before it could clean up. Restoring it would pin the user to a dead listener
// forever. So a captured value that is OUR OWN listener is recorded as "off"
// instead, and Revert disables rather than restores.
//
// The identity test is exact: the host:port (or URL, or resolver address) the
// Op is about to install. "Any loopback address" is not the test, and treating
// it as one destroys the user's local DNS resolver, local web proxy, PAC and
// proxy environment variables on a clean exit. The only concession is
// Env.PriorResidue: when the journal or lock file shows that a previous run
// died mid-flight, a loopback value we cannot match exactly is discarded too,
// because that run may have bound a different port.

// notSelfPAC returns the captured auto-proxy URL unless it is ours.
//
// "Ours" is decided by identity, not by loopback. The Op knows the exact URL it
// is about to install, so an exact match is our own SIGKILL residue and nothing
// else. Loopback on its own proves nothing: a user running mitmproxy, Charles,
// or a corporate PAC served from 127.0.0.1 has a perfectly ordinary
// configuration that must survive our teardown. The loopback test is reached
// only when priorResidue says a previous dpb run died without cleaning up —
// the one situation where a loopback value we cannot match exactly (a previous
// run bound a different port) is more likely to be our dead listener than the
// user's own setting.
func notSelfPAC(rawURL, ourURL string, priorResidue bool) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || rawURL == strings.TrimSpace(ourURL) {
		return ""
	}
	if !priorResidue {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if isLoopbackHost(u.Hostname()) {
		return ""
	}
	return rawURL
}

// notSelfHost returns host unless it names our own listener. host:port is
// compared against the host:port this Op is about to install; see notSelfPAC
// for why loopback alone is not the test.
func notSelfHost(host string, port int, ourHost string, ourPort int, priorResidue bool) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if port == ourPort && sameHost(host, ourHost) {
		return ""
	}
	if priorResidue && isLoopbackHost(host) {
		return ""
	}
	return host
}

// sameHost compares two host fields, tolerating the ways the same address can
// be written (bracketed IPv6, v4-mapped, differing case in a name).
func sameHost(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	ipa, erra := netip.ParseAddr(strings.Trim(a, "[]"))
	ipb, errb := netip.ParseAddr(strings.Trim(b, "[]"))
	return erra == nil && errb == nil && ipa.Unmap() == ipb.Unmap()
}

// notSelfServers drops our own resolver from a captured resolver list.
//
// networksetup carries no port for a resolver, so the only identity available
// is "exactly one of the addresses we are about to install". Even that is not
// enough on its own: a user running dnscrypt-proxy or AdGuard Home on 127.0.0.1
// — the standard defence against precisely the per-QNAME drop and 195.175.254.2
// sinkhole MEASUREMENTS.md §2 records on this line — has the same address we
// would install. Dropping it would revert
// the machine to the ISP's poisoning resolver with `-setdnsservers <svc> Empty`
// and, because the emptied list is what goes in the journal, Replay could not
// restore it either. So an entry is dropped only when priorResidue also says a
// previous dpb run died without cleaning up.
func notSelfServers(servers, ours []string, priorResidue bool) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if priorResidue && isLoopbackHost(s) && containsHost(ours, s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func containsHost(list []string, host string) bool {
	for _, h := range list {
		if sameHost(h, host) {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return a.IsLoopback()
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// marshalRevert encodes an Op's revert payload. A payload that cannot be
// encoded is a programming error we would rather see as a failed mutation than
// as an unrevertable one, so the error is returned, never swallowed.
func marshalRevert(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("netstate: encode revert payload: %w", err)
	}
	return json.RawMessage(b), nil
}

func unmarshalRevert(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("netstate: journal record carries no revert payload")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("netstate: decode revert payload: %w", err)
	}
	return nil
}
