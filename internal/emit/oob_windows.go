//go:build windows

package emit

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/strategy"
)

// oobCaps: Winsock implements MSG_OOB, so the last rung of the measured
// Turkey ladder is available here. Whether it performs the same against Türk
// Telekom's DPI from a Windows TCP stack is unmeasured — see
// docs/MEASUREMENTS.md §4 and Plan 6, which re-measures rather than assumes.
const oobCaps = strategy.CapOOB

// sendOOB writes b as TCP urgent data on the socket behind rc.
//
// It uses windows.WSASend with MSG_OOB and NOT syscall.Sendto: on Windows,
// Sendto is a stub that returns EWINDOWS unconditionally
// ($GOROOT/src/syscall/syscall_windows.go:1193, "func Sendto(...) { return
// EWINDOWS }"). Reaching for the obvious analogue of the darwin
// unix.SendmsgN call would grant CapOOB for a code path that can never
// succeed.
//
// It goes through RawConn.Control rather than RawConn.Write, which is the
// opposite of oob_darwin.go's choice — deliberately, not by oversight.
// oob_darwin.go uses Write because its callback's bool return has a real
// contract on that platform: returning false parks the goroutine on the
// runtime network poller until the fd is writable, so an EAGAIN there is
// answered by waiting rather than spinning. That contract does not exist on
// Windows. internal/poll's Windows RawWrite is a stub:
//
//	func (fd *FD) RawWrite(f func(uintptr) bool) error {
//	    ...
//	    if f(uintptr(fd.Sysfd)) { return nil }
//	    // TODO(tmm1): find a way to detect socket writability
//	    return syscall.EWINDOWS
//	}
//
// ($GOROOT/src/internal/poll/fd_windows.go). Returning false from the
// callback does not park anything — it immediately fails the whole call with
// EWINDOWS. Reaching for Write here would look like it matched darwin's
// behaviour while actually turning a plain WSAEWOULDBLOCK into a hard
// failure on every occurrence. Control carries no such gap: its Windows
// implementation is internal/poll's fd_posix.go RawControl, shared verbatim
// with unix builds, which just invokes the callback with the fd under the
// same incref/decref protection Write uses — no busy-spin risk, because
// there is nothing to retry inside the callback in the first place, and no
// race with a concurrent Close either. So this uses Control and lets
// WSASend's result — including WSAEWOULDBLOCK, on a blocking Winsock socket
// a genuine and rare error rather than the routine flow-control signal
// EAGAIN is on Unix — propagate to the caller as-is.
//
// This is the SECOND stub of this class this plan has found in Go's own
// Windows runtime, after syscall.Sendto above: a Unix-shaped API that exists
// on Windows in name only. Do not "fix" this back to RawConn.Write on the
// assumption that it must be the more capable choice because it is on
// darwin — on this platform it is the one with the gap, not the one without.
func sendOOB(rc syscall.RawConn, b []byte) (int, error) {
	if rc == nil {
		return 0, fmt.Errorf("emit: send MSG_OOB: no raw conn")
	}
	if len(b) == 0 {
		return 0, fmt.Errorf("emit: send MSG_OOB: empty urgent byte")
	}
	var (
		sent  uint32
		opErr error
	)
	if err := rc.Control(func(fd uintptr) {
		buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
		opErr = windows.WSASend(windows.Handle(fd), &buf, 1, &sent, windows.MSG_OOB, nil, nil)
	}); err != nil {
		return 0, fmt.Errorf("emit: send MSG_OOB: %w", err)
	}
	if opErr != nil {
		return int(sent), fmt.Errorf("emit: send MSG_OOB: %w", opErr)
	}
	return int(sent), nil
}
