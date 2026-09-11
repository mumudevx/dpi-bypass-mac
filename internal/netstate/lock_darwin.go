//go:build darwin

package netstate

import (
	"time"

	"golang.org/x/sys/unix"
)

// kernelProcessStart reads pid's start time from the kernel's own proc table.
//
// KERN_PROC_PID hands back a kinfo_proc whose p_starttime is a struct timeval
// filled in by the kernel at fork time: an absolute instant, in no locale, from
// no subprocess. That is the whole reason ProcessStart does not parse ps.
func kernelProcessStart(pid int) (time.Time, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return time.Time{}, false
	}
	tv := kp.Proc.P_starttime
	if tv.Sec == 0 && tv.Usec == 0 {
		return time.Time{}, false
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*1000), true
}
