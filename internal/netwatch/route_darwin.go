package netwatch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/mumudevx/dpb/internal/flow"
)

// RouteSource is the PF_ROUTE reader: the kernel tells us the routing table
// changed instead of us polling it.
//
// The socket is openable by an ordinary user — netstate's AF_ROUTE reader is
// verified doing exactly that on this machine (19,808 bytes / 121 messages as
// uid 501) — which matters because the proxy front end runs without sudo and
// still has to notice that the network moved underneath it.
type RouteSource struct {
	// Types, when set, replaces interestingTypes. It exists for tests and for
	// a future front end that cares about a message kind this one ignores.
	Types map[byte]bool
	Logf  func(string, ...any)
}

var _ Source = (*RouteSource)(nil)

// NewRouteSource returns the shipped Source.
func NewRouteSource() *RouteSource { return &RouteSource{} }

func newDefaultSource() Source { return NewRouteSource() }

// routeBufSize is the read buffer. A routing socket delivers one message per
// read and truncates anything longer, so this only has to exceed the largest
// rt_msghdr plus its sockaddrs; 2 KiB is several times that.
const routeBufSize = 2048

// Routing-message types worth waking up for.
//
// The filter is not an optimisation. RTM_MISS and RTM_LOSING fire on ordinary
// traffic to unreachable addresses — which is constant on a laptop with a
// half-configured network — and every one of them would otherwise cost a facts
// collection, three scutil invocations and a portal probe. What is left is the
// set that actually means the machine's network identity may have moved:
// routes appearing or disappearing, an interface changing state, an address
// being added or removed.
const (
	rtmAdd     = 0x1  // RTM_ADD
	rtmDelete  = 0x2  // RTM_DELETE
	rtmChange  = 0x3  // RTM_CHANGE
	rtmIfInfo  = 0xe  // RTM_IFINFO
	rtmNewAddr = 0xc  // RTM_NEWADDR
	rtmDelAddr = 0xd  // RTM_DELADDR
	rtmIfInfo2 = 0x12 // RTM_IFINFO2
)

var interestingTypes = map[byte]bool{
	rtmAdd:     true,
	rtmDelete:  true,
	rtmChange:  true,
	rtmIfInfo:  true,
	rtmNewAddr: true,
	rtmDelAddr: true,
	rtmIfInfo2: true,
}

func (s *RouteSource) types() map[byte]bool {
	if s.Types != nil {
		return s.Types
	}
	return interestingTypes
}

func (s *RouteSource) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	}
}

// openRoute is a test seam. The read loop's filtering and coalescing are
// ordinary logic that must be tested; the socket itself is a syscall leaf. A
// test substitutes an os.Pipe and writes synthesised routing messages into it.
var openRoute = openRouteSocket

// Run reads routing messages until ctx is done.
//
// The blocking read is interrupted by closing the socket from a second
// goroutine, which is the only way to unblock it: the fd is registered with
// Go's poller (os.NewFile over a non-blocking socket), so Close makes the
// pending Read return ErrClosed rather than leaving a goroutine parked in the
// kernel for the life of the process.
func (s *RouteSource) Run(ctx context.Context, out chan<- struct{}) error {
	f, err := openRoute()
	if err != nil {
		return err
	}
	var once sync.Once
	shut := func() { once.Do(func() { _ = f.Close() }) }

	stop := make(chan struct{})
	closed := make(chan struct{})
	flow.Safe("netwatch/route-close", s.Logf, func() {
		defer close(closed)
		select {
		case <-ctx.Done():
		case <-stop:
		}
		shut()
	})
	defer func() {
		close(stop)
		<-closed
		shut()
	}()

	buf := make([]byte, routeBufSize)
	want := s.types()
	for {
		n, err := f.Read(buf)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return fmt.Errorf("netwatch: read the routing socket: %w", err)
		}
		t, ok := messageType(buf[:n])
		if !ok || !want[t] {
			continue
		}
		s.logf("netwatch: routing message type 0x%x", t)
		// Coalesce. The watcher debounces anyway, and a full channel means a
		// signal it has not yet acted on — one more adds nothing and blocking
		// here would stall the reader while the kernel's socket buffer fills.
		select {
		case out <- struct{}{}:
		default:
		}
	}
}

func openRouteSocket() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("netwatch: open the routing socket: %w", err)
	}
	// Non-blocking BEFORE os.NewFile, so the runtime registers the fd with
	// kqueue instead of dedicating an OS thread to a blocking read.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netwatch: set the routing socket non-blocking: %w", err)
	}
	return os.NewFile(uintptr(fd), "pf_route"), nil
}

// messageType reads rtm_type out of a routing message.
//
// struct rt_msghdr begins u_short rtm_msglen; u_char rtm_version; u_char
// rtm_type, so the type is the fourth byte and the length is the first two in
// host order. The header is read by hand rather than through
// golang.org/x/net/route because that package parses a RIB *dump* and rejects
// message kinds a live socket delivers; all that is needed here is "something
// worth re-reading the table happened".
func messageType(b []byte) (byte, bool) {
	if len(b) < 4 {
		return 0, false
	}
	if l := int(binary.NativeEndian.Uint16(b[:2])); l < 4 || l > len(b) {
		// A truncated or nonsensical message is not evidence of anything. It
		// is dropped rather than treated as a change, because inventing a
		// network change out of a parse failure would make a kernel we do not
		// understand into a revalidation loop.
		return 0, false
	}
	if b[2] != unix.RTM_VERSION {
		return 0, false
	}
	return b[3], true
}
