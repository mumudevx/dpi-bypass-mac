package sysnet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// proxyState is one networksetup proxy entry (web, secure, or socks).
type proxyState struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    string `json:"port"`
}

// serviceBackup captures a network service's proxy state for restoration.
type serviceBackup struct {
	Service string     `json:"service"`
	Web     proxyState `json:"web"`
	Secure  proxyState `json:"secure"`
	Socks   proxyState `json:"socks"`
}

// ProxyManager configures and restores the macOS system proxy.
type ProxyManager struct {
	runner    CommandRunner
	host      string
	httpPort  int
	socksPort int // 0 disables socks configuration
	statePath string
	logf      func(string, ...any)

	// services, if set, overrides auto-detection (used in tests / explicit cfg).
	services []string
	backups  []serviceBackup
}

// ProxyConfig configures a ProxyManager.
type ProxyConfig struct {
	Runner    CommandRunner
	Host      string
	HTTPPort  int
	SocksPort int
	StatePath string
	Services  []string
	Logf      func(string, ...any)
}

// NewProxyManager builds a ProxyManager.
func NewProxyManager(c ProxyConfig) *ProxyManager {
	if c.Runner == nil {
		c.Runner = ExecRunner{}
	}
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.StatePath == "" {
		c.StatePath = DefaultStatePath()
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return &ProxyManager{
		runner:    c.Runner,
		host:      c.Host,
		httpPort:  c.HTTPPort,
		socksPort: c.SocksPort,
		statePath: c.StatePath,
		services:  c.Services,
		logf:      c.Logf,
	}
}

// DefaultStatePath returns ~/.local/state/dpb/proxy-backup.json.
func DefaultStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "state", "dpb", "proxy-backup.json")
}

// Enable captures the current proxy state for each target service, persists it,
// and points the services at the local proxy.
func (m *ProxyManager) Enable(ctx context.Context) error {
	services, err := m.targetServices(ctx)
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return fmt.Errorf("no active network service found")
	}

	m.backups = m.backups[:0]
	for _, svc := range services {
		b := serviceBackup{
			Service: svc,
			Web:     m.getProxy(ctx, "-getwebproxy", svc),
			Secure:  m.getProxy(ctx, "-getsecurewebproxy", svc),
			Socks:   m.getProxy(ctx, "-getsocksfirewallproxy", svc),
		}
		m.backups = append(m.backups, b)
	}
	if err := m.persistBackups(); err != nil {
		m.logf("sysnet: could not persist proxy backup: %v", err)
	}

	port := strconv.Itoa(m.httpPort)
	for _, svc := range services {
		m.set(ctx, "-setwebproxy", svc, m.host, port)
		m.set(ctx, "-setwebproxystate", svc, "on")
		m.set(ctx, "-setsecurewebproxy", svc, m.host, port)
		m.set(ctx, "-setsecurewebproxystate", svc, "on")
		if m.socksPort > 0 {
			m.set(ctx, "-setsocksfirewallproxy", svc, m.host, strconv.Itoa(m.socksPort))
			m.set(ctx, "-setsocksfirewallproxystate", svc, "on")
		}
	}
	return nil
}

// Restore re-applies the captured proxy state. It is idempotent and safe to call
// more than once (e.g. from both a deferred cleanup and a signal handler).
func (m *ProxyManager) Restore(ctx context.Context) {
	if len(m.backups) == 0 {
		m.backups = m.loadBackups()
	}
	for _, b := range m.backups {
		m.restoreOne(ctx, b.Service, "-setwebproxy", "-setwebproxystate", b.Web)
		m.restoreOne(ctx, b.Service, "-setsecurewebproxy", "-setsecurewebproxystate", b.Secure)
		if m.socksPort > 0 {
			m.restoreOne(ctx, b.Service, "-setsocksfirewallproxy", "-setsocksfirewallproxystate", b.Socks)
		}
	}
	m.clearBackups()
	m.backups = nil
}

func (m *ProxyManager) restoreOne(ctx context.Context, svc, setCmd, stateCmd string, st proxyState) {
	if st.Enabled && st.Server != "" {
		m.set(ctx, setCmd, svc, st.Server, portOr(st.Port, "0"))
		m.set(ctx, stateCmd, svc, "on")
	} else {
		m.set(ctx, stateCmd, svc, "off")
	}
}

// targetServices returns the configured services or auto-detects the service
// carrying the default route, falling back to all enabled services.
func (m *ProxyManager) targetServices(ctx context.Context) ([]string, error) {
	if len(m.services) > 0 {
		return m.services, nil
	}
	if svc := m.defaultRouteService(ctx); svc != "" {
		return []string{svc}, nil
	}
	return m.enabledServices(ctx)
}

func (m *ProxyManager) enabledServices(ctx context.Context) ([]string, error) {
	out, err := m.runner.Run(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	var services []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if i == 0 || line == "" { // first line is an explanatory header
			continue
		}
		if strings.HasPrefix(line, "*") { // disabled service
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

var (
	defaultIfaceRe = regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)`)
	svcOrderRe     = regexp.MustCompile(`(?m)^\(\d+\)\s+(.+)$`)
	deviceRe       = regexp.MustCompile(`Device:\s*(\w+)\)`)
)

// defaultRouteService maps the default-route interface to its service name.
func (m *ProxyManager) defaultRouteService(ctx context.Context) string {
	routeOut, err := m.runner.Run(ctx, "route", "-n", "get", "default")
	if err != nil {
		return ""
	}
	mm := defaultIfaceRe.FindStringSubmatch(routeOut)
	if mm == nil {
		return ""
	}
	iface := mm[1]

	orderOut, err := m.runner.Run(ctx, "networksetup", "-listnetworkserviceorder")
	if err != nil {
		return ""
	}
	lines := strings.Split(orderOut, "\n")
	for i := 0; i < len(lines); i++ {
		name := svcOrderRe.FindStringSubmatch(lines[i])
		if name == nil {
			continue
		}
		if i+1 < len(lines) {
			if dev := deviceRe.FindStringSubmatch(lines[i+1]); dev != nil && dev[1] == iface {
				return strings.TrimSpace(name[1])
			}
		}
	}
	return ""
}

func (m *ProxyManager) getProxy(ctx context.Context, cmd, svc string) proxyState {
	out, err := m.runner.Run(ctx, "networksetup", cmd, svc)
	if err != nil {
		return proxyState{}
	}
	return parseProxyState(out)
}

func (m *ProxyManager) set(ctx context.Context, args ...string) {
	full := append([]string{}, args...)
	if _, err := m.runner.Run(ctx, "networksetup", full...); err != nil {
		m.logf("sysnet: networksetup %s: %v", strings.Join(full, " "), err)
	}
}

func parseProxyState(out string) proxyState {
	var st proxyState
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			st.Enabled = strings.EqualFold(v, "Yes")
		case "Server":
			st.Server = v
		case "Port":
			st.Port = v
		}
	}
	return st
}

func (m *ProxyManager) persistBackups() error {
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

func (m *ProxyManager) loadBackups() []serviceBackup {
	if m.statePath == "" {
		return nil
	}
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		return nil
	}
	var b []serviceBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil
	}
	return b
}

func (m *ProxyManager) clearBackups() {
	if m.statePath != "" {
		_ = os.Remove(m.statePath)
	}
}

func portOr(p, def string) string {
	if p == "" || p == "0" {
		return def
	}
	return p
}
