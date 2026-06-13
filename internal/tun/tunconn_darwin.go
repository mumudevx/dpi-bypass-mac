//go:build darwin

package tun

import (
	"net"

	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"golang.org/x/sys/unix"
)

// tunConn adapts an upstream kernel socket to desync.Conn for the TUN path,
// exposing a per-connection RawInjector so fake-packet emitters can craft
// decoys for this flow's 4-tuple.
type tunConn struct {
	*net.TCPConn
	inj desync.RawInjector
}

func (c tunConn) SetTTL(ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
	}); err != nil {
		return err
	}
	return serr
}

func (c tunConn) RawInjector() desync.RawInjector { return c.inj }
