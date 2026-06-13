package proxy

import (
	"net"

	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"golang.org/x/sys/unix"
)

// proxyConn adapts an outbound *net.TCPConn to desync.Conn. SetTTL is honoured
// via setsockopt; RawInjector is nil because the proxy front-end has no
// packet-level access (that is the TUN front-end's job).
type proxyConn struct {
	*net.TCPConn
}

func (c proxyConn) SetTTL(ttl int) error {
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

func (c proxyConn) RawInjector() desync.RawInjector { return nil }
