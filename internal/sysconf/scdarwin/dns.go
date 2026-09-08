//go:build darwin

package scdarwin

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mumudevx/dpb/internal/sysport"
)

type dnsCtl struct{ p *port }

var _ sysport.DNSController = dnsCtl{}

// Configured reads one service's stored resolvers with networksetup — the same
// subsystem Set writes to, so it is for capture and never for verification.
func (c dnsCtl) Configured(ctx context.Context, svc string) ([]string, error) {
	res := c.p.run.Run(ctx, "networksetup", "-getdnsservers", svc)
	if err := res.Error(); err != nil {
		return nil, err
	}
	return parseDNSServers(res.Combined), nil
}

func (c dnsCtl) Set(ctx context.Context, svc string, servers []string) error {
	args := append([]string{"-setdnsservers", svc}, servers...)
	return c.p.run.Run(ctx, "networksetup", args...).Error()
}

// Clear restores svc to DHCP-supplied resolvers. "Empty" is networksetup's
// documented way of saying "back to DHCP".
func (c dnsCtl) Clear(ctx context.Context, svc string) error {
	return c.p.run.Run(ctx, "networksetup", "-setdnsservers", svc, "Empty").Error()
}

// Live reads the resolvers the system actually consults with `scutil --dns`,
// which reports the configuration mDNSResponder is using rather than the
// preference networksetup wrote.
func (c dnsCtl) Live(ctx context.Context) ([]string, error) {
	rs, err := readDNSResolvers(ctx, c.p.env())
	if err != nil {
		return nil, err
	}
	return primaryNameservers(rs), nil
}

// parseDNSServers reads `networksetup -getdnsservers`, which prints one address
// per line, or a sentence when there are none.
func parseDNSServers(out string) []string {
	var servers []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "aren't any DNS Servers") {
			continue
		}
		servers = append(servers, line)
	}
	return servers
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

// ReadDNSResolvers runs `scutil --dns` and parses the resolver blocks.
func ReadDNSResolvers(ctx context.Context, e Env) ([]DNSResolver, error) {
	return readDNSResolvers(ctx, e)
}

// PrimaryNameservers is the unscoped resolver list, which is what an ordinary
// lookup on this machine uses.
func PrimaryNameservers(rs []DNSResolver) []string { return primaryNameservers(rs) }
