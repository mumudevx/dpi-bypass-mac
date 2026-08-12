package sysnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// dnsBackup captures a network service's resolver list for restoration.
type dnsBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

// DNSManager points a network service's resolvers at an address the TUN
// datapath can intercept, and puts the original list back afterwards.
//
// It exists because the common case — a DHCP-provided resolver on the LAN —
// cannot be captured by routing. That address is on-link, so the subnet route
// beats the split-default pair, and it is usually the default gateway as well,
// whose next hop must keep working. Redirecting the service is the only way
// those queries reach dpb at all.
type DNSManager struct {
	runner    CommandRunner
	resolver  string
	statePath string
	services  []string
	backups   []dnsBackup
	logf      func(string, ...any)
}

// DNSConfig configures a DNSManager.
type DNSConfig struct {
	Runner    CommandRunner
	Resolver  string // address to point the service at while dpb runs
	StatePath string
	Services  []string // overrides auto-detection (tests / explicit config)
	Logf      func(string, ...any)
}

// NewDNSManager builds a DNSManager.
func NewDNSManager(c DNSConfig) *DNSManager {
	if c.Runner == nil {
		c.Runner = ExecRunner{}
	}
	if c.Resolver == "" {
		c.Resolver = DefaultTunResolver
	}
	if c.StatePath == "" {
		c.StatePath = DefaultDNSStatePath()
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return &DNSManager{
		runner:    c.Runner,
		resolver:  c.Resolver,
		statePath: c.StatePath,
		services:  c.Services,
		logf:      c.Logf,
	}
}

// DefaultTunResolver is the address the system is pointed at while TUN mode
// runs. It is deliberately a real public resolver rather than an address inside
// the tunnel: queries to it are captured by the split-default routes and
// answered in-process, but if dpb dies without restoring, name resolution
// degrades to plaintext DNS instead of failing outright.
const DefaultTunResolver = "1.1.1.1"

// DefaultDNSStatePath returns ~/.local/state/dpb/dns-backup.json.
func DefaultDNSStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "state", "dpb", "dns-backup.json")
}

// Enable records the current resolvers for each target service, persists them,
// and points the services at the captured resolver.
func (m *DNSManager) Enable(ctx context.Context) error {
	services, err := targetServices(ctx, m.runner, m.services)
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return fmt.Errorf("no active network service found")
	}

	m.backups = m.backups[:0]
	for _, svc := range services {
		m.backups = append(m.backups, dnsBackup{
			Service: svc,
			Servers: m.notSelf(m.getServers(ctx, svc)),
		})
	}
	if err := m.persist(); err != nil {
		m.logf("sysnet: could not persist dns backup: %v", err)
	}

	for _, svc := range services {
		m.set(ctx, "-setdnsservers", svc, m.resolver)
	}
	return nil
}

// Restore puts the captured resolver lists back. It is idempotent.
func (m *DNSManager) Restore(ctx context.Context) {
	if len(m.backups) == 0 {
		m.backups = m.load()
	}
	for _, b := range m.backups {
		args := []string{"-setdnsservers", b.Service}
		if len(b.Servers) == 0 {
			// "Empty" is how networksetup hands the service back to DHCP.
			args = append(args, "Empty")
		} else {
			args = append(args, b.Servers...)
		}
		m.set(ctx, args...)
	}
	m.clear()
	m.backups = nil
}

// notSelf drops our own resolver from a captured list. A run killed with -9
// leaves it in the service config; recording it as the user's original would
// pin them to it permanently.
func (m *DNSManager) notSelf(servers []string) []string {
	var out []string
	for _, s := range servers {
		if s == m.resolver {
			continue
		}
		out = append(out, s)
	}
	return out
}

// getServers reads a service's static resolvers. networksetup answers "There
// aren't any DNS Servers set on X." for a DHCP-provided list, which parses to
// no entries — the right backup, since restoring means handing it back to DHCP.
func (m *DNSManager) getServers(ctx context.Context, svc string) []string {
	out, err := m.runner.Run(ctx, "networksetup", "-getdnsservers", svc)
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if net.ParseIP(line) == nil {
			continue
		}
		servers = append(servers, line)
	}
	return servers
}

func (m *DNSManager) set(ctx context.Context, args ...string) {
	if _, err := m.runner.Run(ctx, "networksetup", args...); err != nil {
		m.logf("sysnet: networksetup %s: %v", strings.Join(args, " "), err)
	}
}

func (m *DNSManager) persist() error {
	if m.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.backups, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.statePath, data, 0o644)
}

func (m *DNSManager) load() []dnsBackup {
	if m.statePath == "" {
		return nil
	}
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		return nil
	}
	var b []dnsBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil
	}
	return b
}

func (m *DNSManager) clear() {
	if m.statePath != "" {
		_ = os.Remove(m.statePath)
	}
}
