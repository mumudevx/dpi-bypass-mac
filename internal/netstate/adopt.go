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
// forever. So a captured value that points at our own loopback listeners is
// recorded as "off" instead, and Revert disables rather than restores.

// notSelfPAC returns the captured auto-proxy URL unless it points at a loopback
// address, in which case it returns "" and Revert will turn the PAC off.
//
// Loopback is the test rather than an exact host:port match because we cannot
// know which port a previous run used, and nothing but a local proxy ever
// legitimately serves a system PAC from 127.0.0.1.
func notSelfPAC(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
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

// notSelfHost returns host unless it is one of our own loopback listeners.
func notSelfHost(host string) string {
	if isLoopbackHost(strings.TrimSpace(host)) {
		return ""
	}
	return strings.TrimSpace(host)
}

// notSelfServers drops loopback entries from a captured resolver list. If that
// empties the list, Revert clears the service's resolvers rather than restoring
// a pointer at a resolver that is no longer listening.
func notSelfServers(servers []string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" || isLoopbackHost(s) {
			continue
		}
		out = append(out, s)
	}
	return out
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
