//go:build darwin

package emit

import (
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// sockTTLCaps is what a Darwin kernel socket grants for hop-limit control.
// GT11 verified on Darwin 25.3.0 that per-segment IP_TTL=1 works and is race-free
// with TCP_NODELAY: after send(40) with TTL=1, txpackets went to 1 immediately;
// after restore + send(24), txpackets went to 2; at 50 ms txpackets was 3 with
// txretransmitbytes=40, i.e. only the dropped segment was retransmitted.
const sockTTLCaps = strategy.CapSockTTL | strategy.CapUDPTTL

const (
	sysctlTTLv4 = "net.inet.ip.ttl"
	sysctlTTLv6 = "net.inet6.ip6.hlim"
)

type cachedTTL struct {
	once sync.Once
	val  int
	err  error
}

func (c *cachedTTL) get(name string) (int, error) {
	c.once.Do(func() { c.val, c.err = readTTLSysctl(name) })
	return c.val, c.err
}

var (
	ttlV4 cachedTTL
	ttlV6 cachedTTL
)

// DefaultTTL reads net.inet.ip.ttl instead of hardcoding 64 (DOSSIER §3: "read
// the real default TTL rather than hardcoding 64"; verified net.inet.ip.ttl = 64
// on the development machine, 2026-09-02). It is a boot-time tunable a user may
// have changed, and restoring the wrong value after a disorder segment would
// silently alter every later packet on the connection.
//
// The read is cached: it cannot change under a running process in any way that
// matters, and the desync path would otherwise pay a sysctl per connection.
func DefaultTTL() (int, error) { return ttlV4.get(sysctlTTLv4) }

// defaultHopLimit is DefaultTTL's family-aware form. IPv6 has its own tunable,
// net.inet6.ip6.hlim, and restoring an IPv6 socket to the IPv4 default would be
// wrong on any machine where the two differ.
func defaultHopLimit(v6 bool) (int, error) {
	if v6 {
		if n, err := ttlV6.get(sysctlTTLv6); err == nil {
			return n, nil
		}
		// A kernel with IPv6 disabled has no ip6.hlim; the socket still has a
		// default hop limit and the v4 tunable is the honest approximation.
		return DefaultTTL()
	}
	return DefaultTTL()
}

func readTTLSysctl(name string) (int, error) {
	v, err := unix.SysctlUint32(name)
	if err != nil {
		return 0, fmt.Errorf("emit: sysctl %s: %w", name, err)
	}
	if v < 1 || v > 255 {
		return 0, fmt.Errorf("emit: sysctl %s reported %d, want 1..255", name, v)
	}
	return int(v), nil
}

// setHopLimit sets IP_TTL or IPV6_UNICAST_HOPS on the socket behind rc.
//
// It tries the family implied by v6 first and falls back to the other. A
// dual-stack listener can hand us an AF_INET6 socket whose peer is v4-mapped, and
// guessing the family wrong there is the difference between a working disorder
// rung and a setsockopt that returns EINVAL on every attempt.
func setHopLimit(rc syscall.RawConn, v6 bool, ttl int) error {
	if rc == nil {
		return fmt.Errorf("emit: set hop limit %d: no raw conn", ttl)
	}
	var first, second error
	if err := rc.Control(func(fd uintptr) {
		lvl, opt := hopOpt(v6)
		first = unix.SetsockoptInt(int(fd), lvl, opt, ttl)
		if first != nil {
			lvl, opt = hopOpt(!v6)
			second = unix.SetsockoptInt(int(fd), lvl, opt, ttl)
		}
	}); err != nil {
		return fmt.Errorf("emit: set hop limit %d: raw control: %w", ttl, err)
	}
	if first != nil && second != nil {
		return fmt.Errorf("emit: set hop limit %d: %w", ttl, first)
	}
	return nil
}

func getHopLimit(rc syscall.RawConn, v6 bool) (int, error) {
	if rc == nil {
		return 0, fmt.Errorf("emit: read hop limit: no raw conn")
	}
	var (
		val           int
		first, second error
		altVal        int
	)
	if err := rc.Control(func(fd uintptr) {
		lvl, opt := hopOpt(v6)
		val, first = unix.GetsockoptInt(int(fd), lvl, opt)
		if first != nil {
			lvl, opt = hopOpt(!v6)
			altVal, second = unix.GetsockoptInt(int(fd), lvl, opt)
		}
	}); err != nil {
		return 0, fmt.Errorf("emit: read hop limit: raw control: %w", err)
	}
	if first == nil {
		return val, nil
	}
	if second == nil {
		return altVal, nil
	}
	return 0, fmt.Errorf("emit: read hop limit: %w", first)
}

func hopOpt(v6 bool) (level, opt int) {
	if v6 {
		return unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	}
	return unix.IPPROTO_IP, unix.IP_TTL
}
