//go:build darwin

package emit

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// oobCaps: MSG_OOB (0x1) exists in the Darwin SDK and `oob:pos=1` scored 3/3 on
// all three blocked targets in MEASUREMENTS.md §3 — the last rung of the shipped
// ladder, and the only technique in the one macOS-on-TT recipe reported working.
const oobCaps = strategy.CapOOB

// sendOOB writes b as TCP urgent data on the socket behind rc.
//
// It goes through RawConn.Write rather than RawConn.Control + Sendto, which is
// what the dossier sketched. The difference is the callback's return value:
// Write's callback returns a bool, and returning false parks the goroutine on
// Go's runtime network poller until the fd is writable again. Control's callback
// returns nothing and carries no such contract, so an EAGAIN there can only be
// answered by spinning on a busy CPU — on the exact code path that runs while a
// user is waiting for a page to load.
//
// Write also holds the conn's reference count for the duration, so a concurrent
// Close cannot pull the fd out from under the sendmsg.
func sendOOB(rc syscall.RawConn, b []byte) (int, error) {
	if rc == nil {
		return 0, fmt.Errorf("emit: send MSG_OOB: no raw conn")
	}
	if len(b) == 0 {
		return 0, fmt.Errorf("emit: send MSG_OOB: empty urgent byte")
	}
	var (
		n     int
		opErr error
	)
	if err := rc.Write(func(fd uintptr) bool {
		n, opErr = unix.SendmsgN(int(fd), b, nil, nil, unix.MSG_OOB)
		// false means "not done, wake me when writable" — the poller handles the
		// wait. EWOULDBLOCK is EAGAIN on Darwin; both are listed for clarity.
		return !errors.Is(opErr, unix.EAGAIN) && !errors.Is(opErr, unix.EWOULDBLOCK)
	}); err != nil {
		return 0, fmt.Errorf("emit: send MSG_OOB: %w", err)
	}
	if opErr != nil {
		return n, fmt.Errorf("emit: send MSG_OOB: %w", opErr)
	}
	return n, nil
}
