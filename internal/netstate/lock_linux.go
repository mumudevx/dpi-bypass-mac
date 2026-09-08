//go:build linux

package netstate

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
)

// kernelProcessStart reads pid's start time from procfs.
//
// Linux has no sysctl equivalent of darwin's KERN_PROC_PID, so the two numbers
// come from two files: field 22 of /proc/<pid>/stat is the process's start time
// in clock ticks after boot, and btime in /proc/stat is the boot instant in
// Unix seconds. Neither is formatted, translated or reordered by a locale, and
// neither costs a subprocess — the properties ProcessStart's comment demands.
//
// Parsing is anchored on the LAST ')' rather than on field boundaries because
// field 2 is the executable's own name in parentheses, and a program is free to
// put spaces and ')' in it. Splitting the whole line would let a hostile or
// merely unlucky process name shift every field after it.
//
// The resolution is a second from btime plus 10ms from the tick, which is
// inside OwnerAlive's two-second tolerance; and a record written by this same
// function compares exactly equal to itself, which is the case that matters.
func kernelProcessStart(pid int) (time.Time, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return time.Time{}, false
	}
	// Fields 3..52 follow the comm field, so field 22 sits at index 22-3.
	const startTimeIndex = 22 - 3
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) <= startTimeIndex {
		return time.Time{}, false
	}
	// Zero is a legitimate value, not a missing one: field 22 counts clock
	// ticks SINCE BOOT, so a process started in the first jiffy — init, and
	// anything a very fast boot forks alongside it — records 0 and is as alive
	// as any other. Rejecting it here would report that process dead, and a
	// dead owner is what makes Replay revert a live run's networking. A
	// NEGATIVE count is the only impossible one, and that is what is rejected.
	ticks, err := strconv.ParseInt(fields[startTimeIndex], 10, 64)
	if err != nil || ticks < 0 {
		return time.Time{}, false
	}
	boot, ok := bootTime()
	if !ok {
		return time.Time{}, false
	}
	// USER_HZ, the userspace ABI constant, is 100 on every architecture Go
	// targets on Linux. It is NOT the kernel's internal CONFIG_HZ and does not
	// move with it. Multiplying by (time.Second / userHZ) rather than dividing
	// afterwards keeps a machine with years of uptime from overflowing int64.
	const userHZ = 100
	return boot.Add(time.Duration(ticks) * (time.Second / userHZ)), true
}

// bootTime reads the boot instant that /proc/<pid>/stat's start time counts
// from. It is a whole number of Unix seconds, which is all procfs publishes.
func bootTime() (time.Time, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil || sec <= 0 {
			return time.Time{}, false
		}
		return time.Unix(sec, 0), true
	}
	return time.Time{}, false
}
