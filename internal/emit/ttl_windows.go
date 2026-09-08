//go:build windows

package emit

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/mumudevx/dpb/internal/strategy"
)

// sockTTLCaps is what Winsock grants for hop-limit control. IP_TTL and
// IPV6_UNICAST_HOPS are ordinary setsockopt/getsockopt options on Windows too
// (see $GOROOT/src/syscall/types_windows.go), reached through the same
// syscall.SetsockoptInt/GetsockoptInt entry points darwin reaches through
// golang.org/x/sys/unix — so both TTL rungs of the Turkey ladder are grantable
// here on the same terms as darwin. Whether a Windows TCP stack reacts to a
// dropped-TTL segment the same way Darwin's does is unmeasured; that is
// docs/MEASUREMENTS.md §4 and Plan 6's question, not an assumption made here.
const sockTTLCaps = strategy.CapSockTTL | strategy.CapUDPTTL

type cachedTTL struct {
	once sync.Once
	val  int
	err  error
}

// get resolves and caches the default hop limit for one address family. v6
// selects IPV6_UNICAST_HOPS; otherwise IP_TTL.
func (c *cachedTTL) get(v6 bool) (int, error) {
	c.once.Do(func() { c.val, c.err = readSocketTTL(v6) })
	return c.val, c.err
}

var (
	ttlV4 cachedTTL
	ttlV6 cachedTTL
)

// DefaultTTL has no Windows analogue of darwin's net.inet.ip.ttl sysctl —
// there is no portable API that reports the machine's default IP_TTL
// directly. So this opens a throwaway UDP socket and reads IP_TTL back off
// it instead: the value the kernel stamps on a brand-new socket *is* the
// machine's default, which answers the same question the sysctl answers on
// darwin, needs no new API, and needs no registry read.
//
// This must not be hardcoded. Windows defaults to 128, where darwin defaults
// to 64 (see ttl_darwin.go, verified net.inet.ip.ttl = 64 on the development
// machine, 2026-09-02): a 64 baked in here would be wrong on every Windows
// machine, and a 128 baked into the darwin file would be wrong on every Mac.
// That is exactly the shortcut DOSSIER §3 warns against.
//
// The read is cached with sync.Once, matching ttl_darwin.go: the default
// cannot change under a running process in any way that matters, and the
// desync path would otherwise pay a socket open+close per connection.
func DefaultTTL() (int, error) { return ttlV4.get(false) }

// defaultHopLimit is DefaultTTL's family-aware form, mirroring ttl_darwin.go.
// IPv6 has its own hop-limit default, so restoring an IPv6 socket to the IPv4
// value would be wrong on any machine where the two differ.
func defaultHopLimit(v6 bool) (int, error) {
	if v6 {
		if n, err := ttlV6.get(true); err == nil {
			return n, nil
		}
		// A machine that cannot open a v6 UDP socket (IPv6 disabled, or no v6
		// route at all) still has a real hop limit on the connection this is
		// serving; the v4 default is the honest approximation, exactly as
		// ttl_darwin.go falls back when ip6.hlim is unreadable.
		return DefaultTTL()
	}
	return DefaultTTL()
}

// readSocketTTL opens a throwaway UDP socket of the given family, reads its
// hop-limit option straight back with getsockopt, and closes it. The socket
// never sends a packet — it exists only so the kernel has stamped a default
// onto something we can ask about.
func readSocketTTL(v6 bool) (int, error) {
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return 0, fmt.Errorf("emit: open throwaway %s socket for default TTL: %w", network, err)
	}
	defer conn.Close()

	sc, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("emit: default TTL: %w", err)
	}

	var (
		val    int
		optErr error
	)
	if err := sc.Control(func(fd uintptr) {
		lvl, opt := hopOpt(v6)
		val, optErr = syscall.GetsockoptInt(syscall.Handle(fd), lvl, opt)
	}); err != nil {
		return 0, fmt.Errorf("emit: default TTL: raw control: %w", err)
	}
	if optErr != nil {
		return 0, fmt.Errorf("emit: getsockopt default TTL: %w", optErr)
	}
	if val < 1 || val > 255 {
		return 0, fmt.Errorf("emit: default TTL socket reported %d, want 1..255", val)
	}
	return val, nil
}

// setHopLimit sets IP_TTL or IPV6_UNICAST_HOPS on the socket behind rc.
//
// It tries the family implied by v6 first and falls back to the other,
// mirroring ttl_darwin.go: a dual-stack listener can hand us an AF_INET6
// socket whose peer is v4-mapped, and guessing the family wrong there is the
// difference between a working disorder rung and a setsockopt that returns
// WSAEINVAL on every attempt.
func setHopLimit(rc syscall.RawConn, v6 bool, ttl int) error {
	if rc == nil {
		return fmt.Errorf("emit: set hop limit %d: no raw conn", ttl)
	}
	var first, second error
	if err := rc.Control(func(fd uintptr) {
		lvl, opt := hopOpt(v6)
		first = syscall.SetsockoptInt(syscall.Handle(fd), lvl, opt, ttl)
		if first != nil {
			lvl, opt = hopOpt(!v6)
			second = syscall.SetsockoptInt(syscall.Handle(fd), lvl, opt, ttl)
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
		val, first = syscall.GetsockoptInt(syscall.Handle(fd), lvl, opt)
		if first != nil {
			lvl, opt = hopOpt(!v6)
			altVal, second = syscall.GetsockoptInt(syscall.Handle(fd), lvl, opt)
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
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}
