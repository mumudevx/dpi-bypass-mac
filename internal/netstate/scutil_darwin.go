package netstate

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The scutil parsers in this file are the independent verifiers. Everything the
// proxy and DNS ops write goes in through networksetup(8) and comes back out
// through scutil(8), which reads the dynamic store the system actually consults
// rather than the preferences plist networksetup wrote.

// ProxyState is `scutil --proxy` reduced to a lookup table. scutil prints a
// flat CFDictionary with one nested array, so a map plus the exceptions list is
// a complete representation.
type ProxyState struct {
	Keys       map[string]string
	Exceptions []string
}

// Str returns the value for key, or "" if absent.
func (p ProxyState) Str(key string) string { return p.Keys[key] }

// On reports whether an scutil boolean key ("0"/"1") is set.
func (p ProxyState) On(key string) bool { return p.Keys[key] == "1" }

// Int returns the value for key as an integer; ok is false if absent or
// unparseable.
func (p ProxyState) Int(key string) (int, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(p.Keys[key]))
	if err != nil {
		return 0, false
	}
	return v, true
}

var scutilKV = regexp.MustCompile(`^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$`)
var scutilArrayEntry = regexp.MustCompile(`^\s*\d+\s*:\s*(.*)$`)

// parseProxyState parses `scutil --proxy`. Nested arrays other than
// ExceptionsList are ignored rather than flattened, because flattening them
// would silently merge keys from different scopes.
func parseProxyState(out string) ProxyState {
	st := ProxyState{Keys: map[string]string{}}
	inArray := ""
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "}" {
			inArray = ""
			continue
		}
		if inArray != "" {
			if m := scutilArrayEntry.FindStringSubmatch(line); m != nil {
				if inArray == "ExceptionsList" {
					st.Exceptions = append(st.Exceptions, strings.TrimSpace(m[1]))
				}
			}
			continue
		}
		m := scutilKV.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		if strings.HasPrefix(val, "<array>") || strings.HasPrefix(val, "<dictionary>") {
			inArray = key
			continue
		}
		st.Keys[key] = val
	}
	return st
}

// readProxyState runs `scutil --proxy` and parses it.
func readProxyState(ctx context.Context, e Env) (ProxyState, error) {
	res := e.runner().Run(ctx, "scutil", "--proxy")
	if err := res.Error(); err != nil {
		return ProxyState{}, fmt.Errorf("netstate: read proxy state: %w", err)
	}
	return parseProxyState(res.Combined), nil
}

// DNSResolver is one resolver block from `scutil --dns`.
type DNSResolver struct {
	Index       int
	Domain      string
	Nameservers []string
	IfIndex     int
	IfName      string
	// Scoped is true for resolvers under the "(for scoped queries)" heading;
	// those are per-interface and are not what an unscoped lookup uses.
	Scoped bool
}

var resolverHeader = regexp.MustCompile(`^resolver #(\d+)`)
var nameserverKey = regexp.MustCompile(`^nameserver\[\d+\]$`)
var ifIndexValue = regexp.MustCompile(`^(\d+)\s*(?:\(([^)]*)\))?`)

// parseDNSResolvers parses `scutil --dns`.
func parseDNSResolvers(out string) []DNSResolver {
	var out2 []DNSResolver
	var cur *DNSResolver
	scoped := false
	flush := func() {
		if cur != nil {
			out2 = append(out2, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "DNS configuration") {
			flush()
			scoped = strings.Contains(trimmed, "scoped")
			continue
		}
		if m := resolverHeader.FindStringSubmatch(trimmed); m != nil {
			flush()
			n, _ := strconv.Atoi(m[1])
			cur = &DNSResolver{Index: n, Scoped: scoped}
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch {
		case nameserverKey.MatchString(key):
			cur.Nameservers = append(cur.Nameservers, val)
		case key == "domain":
			cur.Domain = val
		case key == "if_index":
			if m := ifIndexValue.FindStringSubmatch(val); m != nil {
				cur.IfIndex, _ = strconv.Atoi(m[1])
				cur.IfName = m[2]
			}
		}
	}
	flush()
	return out2
}

// readDNSResolvers runs `scutil --dns` and parses it.
func readDNSResolvers(ctx context.Context, e Env) ([]DNSResolver, error) {
	res := e.runner().Run(ctx, "scutil", "--dns")
	if err := res.Error(); err != nil {
		return nil, fmt.Errorf("netstate: read dns state: %w", err)
	}
	return parseDNSResolvers(res.Combined), nil
}

// primaryNameservers returns the nameservers of the first unscoped resolver,
// which is the list an ordinary lookup consults.
func primaryNameservers(rs []DNSResolver) []string {
	for _, r := range rs {
		if r.Scoped || len(r.Nameservers) == 0 {
			continue
		}
		// mDNSResponder synthesises resolvers for .local and the reverse zones;
		// they are never the system's real upstream.
		if r.Domain != "" {
			continue
		}
		return r.Nameservers
	}
	return nil
}

// NCService is one entry from `scutil --nc list`.
type NCService struct {
	Enabled bool
	Status  string
	ID      string
	Type    string
	Name    string
}

// Connected reports whether the VPN service is up.
func (s NCService) Connected() bool { return strings.EqualFold(s.Status, "Connected") }

// A `scutil --nc list` line is an optional "*" (the service is enabled), a
// parenthesised status, a UUID, a type, a quoted name and a bracketed subtype:
//
//   - (Disconnected) 8F6A1B2C-... PPP (L2TP) "Work VPN" [PPP:L2TP]
var ncLine = regexp.MustCompile(`^(\*?)\s*\(([^)]*)\)\s+(\S+)\s+(.*)$`)
var ncName = regexp.MustCompile(`"([^"]*)"`)

// parseNCList parses `scutil --nc list`.
func parseNCList(out string) []NCService {
	var svcs []NCService
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimRight(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "Available network connection") {
			continue
		}
		m := ncLine.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		svc := NCService{
			Enabled: m[1] == "*",
			Status:  strings.TrimSpace(m[2]),
			ID:      m[3],
		}
		rest := strings.TrimSpace(m[4])
		if n := ncName.FindStringSubmatch(rest); n != nil {
			svc.Name = n[1]
			svc.Type = strings.TrimSpace(rest[:strings.Index(rest, n[0])])
		} else {
			svc.Type = rest
		}
		svcs = append(svcs, svc)
	}
	return svcs
}

// readNCList runs `scutil --nc list`. A machine with no VPN configurations
// still exits 0 with an empty list, so an error here is a real failure.
func readNCList(ctx context.Context, e Env) ([]NCService, error) {
	res := e.runner().Run(ctx, "scutil", "--nc", "list")
	if err := res.Error(); err != nil {
		return nil, fmt.Errorf("netstate: read vpn list: %w", err)
	}
	return parseNCList(res.Combined), nil
}
