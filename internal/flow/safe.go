// Package flow is the shared per-connection engine used by both front ends.
package flow

import (
	"runtime"
	"sync/atomic"
)

// panics counts goroutine panics recovered by Safe for the life of the process.
// `dpb status` reports it: a non-zero value means connections are dying in a
// way nobody has diagnosed yet.
var panics atomic.Uint64

// PanicCount is the number of goroutine panics Safe has recovered.
func PanicCount() uint64 { return panics.Load() }

// PanicHook observes a recovered goroutine panic.
type PanicHook func(name string, v any, stack []byte)

// panicHook is stored atomically rather than as a plain var because it is read
// by every connection goroutine and written by start-up and by tests.
var panicHook atomic.Pointer[PanicHook]

// SetPanicHook installs (or, with nil, removes) the hook called after a
// recovered panic. It exists so the event log can record a panic as a
// first-class event. The hook must not block; if it panics, Safe contains that
// too. It returns the previous hook so a caller can restore it.
func SetPanicHook(h PanicHook) PanicHook {
	var old PanicHook
	if p := panicHook.Swap(hookPtr(h)); p != nil {
		old = *p
	}
	return old
}

func hookPtr(h PanicHook) *PanicHook {
	if h == nil {
		return nil
	}
	return &h
}

// stackBuf caps the captured stack. 64 KiB is enough for the deepest relay
// stack and small enough that a panic storm cannot itself exhaust memory.
const stackBuf = 64 << 10

// Safe spawns fn on a new goroutine with a recover barrier and is the ONLY
// sanctioned goroutine spawn in per-connection code.
//
// Go runs only the panicking goroutine's deferred functions before killing the
// whole process, so a bare `go` in a connection path turns one malformed
// ClientHello into a process death that leaves the system proxy pointed at a
// port nothing is listening on. That is the failure mode this tool exists not
// to have. A build gate (TestNoBareGoroutine) fails the build on a bare `go`
// statement anywhere in front/, flow/ or resolve/.
//
// name identifies the goroutine in the panic report. logf may be nil.
func Safe(name string, logf func(string, ...any), fn func()) {
	go func() {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			panics.Add(1)
			buf := make([]byte, stackBuf)
			n := runtime.Stack(buf, false)
			stack := buf[:n]
			if logf != nil {
				logf("panic in %s: %v\n%s", name, r, stack)
			}
			if p := panicHook.Load(); p != nil {
				// The hook is best effort: a panic inside the panic handler
				// must not take the process down after we already contained
				// the original one.
				defer func() { _ = recover() }()
				(*p)(name, r, stack)
			}
		}()
		fn()
	}()
}
