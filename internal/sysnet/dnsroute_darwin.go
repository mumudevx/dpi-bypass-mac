//go:build darwin

package sysnet

import (
	"context"
	"net"
	"regexp"
)

// nameserverRe matches the `nameserver[N] : ADDR` lines of `scutil --dns`.
var nameserverRe = regexp.MustCompile(`(?m)^\s*nameserver\[\d+\]\s*:\s*(\S+)`)

// ActiveNameservers returns the IPv4 resolvers the system is currently using,
// in first-seen order and deduplicated.
//
// It reads `scutil --dns` rather than `networksetup -getdnsservers` because the
// common case is a DHCP-provided resolver, which networksetup reports as "there
// aren't any DNS servers set".
//
// Loopback resolvers are skipped: a local stub (dnsmasq, a VPN helper) is
// reachable without leaving the host, and a host route for 127.0.0.1 would take
// DNS down instead of protecting it. IPv6 resolvers are skipped because the
// capture routes are IPv4-only.
func ActiveNameservers(ctx context.Context, runner CommandRunner) []string {
	if runner == nil {
		runner = ExecRunner{}
	}
	out, err := runner.Run(ctx, "scutil", "--dns")
	if err != nil {
		return nil
	}

	var servers []string
	seen := make(map[string]bool)
	for _, m := range nameserverRe.FindAllStringSubmatch(out, -1) {
		addr := m[1]
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		servers = append(servers, addr)
	}
	return servers
}

// CaptureHosts routes individual IPv4 addresses through the utun. A /32 is more
// specific than the LAN's subnet route, so it is what pulls a router-provided
// resolver (192.168.1.1 and friends) into the interception path — the
// split-default routes alone leave on-link destinations on the physical link.
//
// Unparseable entries are skipped rather than handed to route(8).
func (r *RouteManager) CaptureHosts(ctx context.Context, addrs []string) error {
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if err := r.AddRoute(ctx, a+"/32"); err != nil {
			return err
		}
	}
	return nil
}
