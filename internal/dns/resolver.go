// Package dns provides an ordered resolver chain (DoH / DoT / plain UDP) with a
// small positive cache. Encrypted DoH defeats ISP DNS poisoning; the chain
// falls back to the next resolver on any failure.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Resolver resolves a host name to one or more IP addresses.
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]net.IP, error)
	Label() string
}

// Chain tries each resolver in order and caches the first success.
type Chain struct {
	resolvers []Resolver
	cache     *cache
	logf      func(format string, args ...any)
}

// NewChain builds a resolver chain with the given positive-cache TTL.
func NewChain(resolvers []Resolver, ttl time.Duration, logf func(string, ...any)) *Chain {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Chain{resolvers: resolvers, cache: newCache(ttl), logf: logf}
}

// Labels returns the resolver labels for the startup banner.
func (c *Chain) Labels() []string {
	out := make([]string, len(c.resolvers))
	for i, r := range c.resolvers {
		out[i] = r.Label()
	}
	return out
}

// Resolve returns IPs for host, using the cache and the fallback chain. If host
// is already an IP literal it is returned as-is.
func (c *Chain) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if ips, ok := c.cache.get(host); ok {
		return ips, nil
	}
	var lastErr error
	for _, r := range c.resolvers {
		ips, err := r.Resolve(ctx, host)
		if err == nil && len(ips) > 0 {
			c.cache.put(host, ips)
			return ips, nil
		}
		if err != nil {
			lastErr = err
			c.logf("dns: %s failed for %s: %v", r.Label(), host, err)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address found for %s", host)
	}
	return nil, fmt.Errorf("resolve %s: %w", host, lastErr)
}

// cache is a tiny TTL map for positive answers.
type cache struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[string]entry
}

type entry struct {
	ips      []net.IP
	expireAt time.Time
}

func newCache(ttl time.Duration) *cache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &cache{ttl: ttl, m: make(map[string]entry)}
}

func (c *cache) get(host string) ([]net.IP, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[host]
	if !ok || time.Now().After(e.expireAt) {
		return nil, false
	}
	return e.ips, true
}

func (c *cache) put(host string, ips []net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[host] = entry{ips: ips, expireAt: time.Now().Add(c.ttl)}
}
