package proxy

import (
	"context"
	"net"

	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
)

// EngineApply adapts a desync.Engine into an ApplyFunc, wrapping the upstream
// TCP connection as a desync.Conn (with setsockopt TTL support).
func EngineApply(e *desync.Engine) ApplyFunc {
	return func(ctx context.Context, upstream *net.TCPConn, first []byte, dstPort int) error {
		return e.Apply(ctx, proxyConn{upstream}, first, dstPort)
	}
}
