//go:build windows

package netwatch

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/windows"
)

// RouteSource is the IP Helper route-change reader: the kernel tells us the
// routing table changed instead of us polling it.
//
// It satisfies exactly the contract route_darwin.go's PF_ROUTE reader does —
// one value on out per routing message, out never closed, a prompt return once
// ctx is done — but the mechanism is inverted, and every design decision below
// falls out of that inversion. There is no socket to read and no descriptor to
// close: NotifyRouteChange2 registers a CALLBACK, Windows invokes it on a
// thread of its own choosing, and deregistration is a separate call that must
// happen before this goroutine goes away. Run is therefore a forwarder rather
// than a reader.
//
// No privilege claim is made here. MSDN documents no access requirement for
// NotifyRouteChange2 — in contrast to, say, SetIfEntry, where it says "requires
// local Administrator privileges" outright — but an absent sentence is not a
// measurement, and nothing in this package has been executed on a Windows host
// (internal/sysconf/scwindows/iphlp_test.go says the same thing about itself).
// If the registration turns out to need elevation, it fails by name through
// Run's error and Watcher.startSource reports it; it does not fail silently.
type RouteSource struct {
	Logf func(string, ...any)
}

var _ Source = (*RouteSource)(nil)

// NewRouteSource returns the shipped Source.
func NewRouteSource() *RouteSource { return &RouteSource{} }

func newDefaultSource() Source { return NewRouteSource() }

func (s *RouteSource) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	}
}

// ErrRouteSourceBusy is a second concurrent Run. See activeReg.
var ErrRouteSourceBusy = errors.New(
	"netwatch: a route-change registration is already live in this process")

// routeReg is the state one live registration shares with the callback.
type routeReg struct {
	// signal has room for one. The callback's send is non-blocking, so a full
	// buffer drops the newer signal — which is the correct behaviour and not a
	// compromise: a pending signal is one the forwarding loop has not acted on
	// yet, the watcher debounces bursts anyway (DefaultDebounce), and all
	// anybody downstream needs to know is THAT something changed.
	//
	// It is never closed, and nothing may ever close it. A send on a closed
	// channel panics, and a panic inside the callback happens on a Windows
	// thread pool thread with none of our frames above it: flow.Safe's recover
	// guards the goroutines this process started, and that thread is not one
	// of them.
	signal chan struct{}
}

// activeReg is the one live registration, or nil.
//
// # Why a package singleton, and why callerContext is nil
//
// NotifyRouteChange2 takes a PVOID CallerContext that it hands back to every
// callback, and the obvious thing to put there — a *RouteSource — is the one
// thing that must not go there. Passing a Go pointer through a C-held
// parameter breaks the cgo pointer-passing rules the runtime enforces as
// cgocheck: Windows keeps that word for the life of the registration, out of
// the garbage collector's sight, with nothing stopping the object it addresses
// from being collected or moved underneath it.
//
// The standard fix is a registry keyed by an integer handle, looked up in the
// callback under a mutex. That is safe from cgocheck and NOT safe from MSDN,
// whose CancelMibChangeNotify2 Remarks rule it out in as many words: "a thread
// that executes the CancelMibChangeNotify2 function cannot own a resource on
// which the thread that executes a notification callback operation would wait
// because it would result in a similar deadlock." A mutex shared between the
// callback and Run's teardown is precisely that resource, and the deadlock it
// buys is a hung shutdown on a user's machine that no test here could ever
// reproduce.
//
// So this source passes NOTHING across the boundary: callerContext is a
// literal nil, the callback takes no lock at all, and the only state it needs
// is one atomically published pointer. There is no Go pointer for cgocheck to
// reject, nothing for the collector to move out from under Windows, and no
// resource for Cancel to deadlock against.
//
// A singleton is sufficient because at most one registration can be wanted:
// Watcher is documented "One per process" and Watcher.Run starts exactly one
// Source. The compare-and-swap in Run makes a second concurrent Run fail by
// name rather than quietly stealing the first one's notifications — a quiet
// theft would leave a watcher permanently blind, which is the exact failure
// route_other.go's comment exists to prevent.
var activeReg atomic.Pointer[routeReg]

// onRouteChange is PIPFORWARD_CHANGE_CALLBACK.
//
// Windows calls it on a thread of its own — a thread pool thread, not a
// goroutine — so it does the least it possibly can: one atomic load and one
// non-blocking send. No lock, no allocation, no logging, no syscall, and above
// all nothing that can block. MSDN: "The invocation of the callback function
// specified in the Callback parameter is serialized", so a callback that
// dawdles does not merely delay this process, it stalls every notification
// queued behind it.
//
// Both parameters after the context are ignored, deliberately. MSDN says the
// Row "contains incomplete data ... only enough information that an
// application can call the GetIpForwardEntry2 function to query complete
// information", and that "The memory pointed to by the Row parameter used in
// the callback indications is managed by the operating system. An application
// that receives a notification should never attempt to free the memory". This
// callback neither dereferences it nor frees it, because the watcher's answer
// to any routing change is to re-collect the machine's facts from scratch —
// which row moved tells it nothing it does not re-read anyway. Nor does
// NotificationType matter: MibInitialNotification cannot arrive here (see
// notifyRoute), so every call is a real change.
//
// The signature is one uintptr per parameter because that is what
// syscall.NewCallback accepts: "The function must not have arguments with size
// larger than the size of uintptr", plus exactly one uintptr-sized result. The
// C function is declared VOID; the zero returned here is the result Go's
// callback ABI requires and Windows discards.
func onRouteChange(callerContext, row, notificationType uintptr) uintptr {
	if reg := activeReg.Load(); reg != nil {
		select {
		case reg.signal <- struct{}{}:
		default:
		}
	}
	return 0
}

// routeChangeCallback is compiled ONCE, at package initialisation, and reused
// by every registration for the life of the process.
//
// syscall.NewCallback's own documentation is the reason: "Only a limited
// number of callbacks may be created in a single Go process, and any memory
// allocated for these callbacks is never released." Watcher.startSource
// re-runs a failed Source forever, once every SourceRetry, so building a
// callback per Run would spend that finite budget one entry per retry and
// eventually panic in a process whose only sin was running a long time on a
// flapping network.
var routeChangeCallback = syscall.NewCallback(onRouteChange)

// notifyRoute and cancelRoute are the test seams, and the only two lines in
// this file that reach the kernel. Everything around them — claiming the
// singleton, forwarding, the teardown ordering — is ordinary logic that has to
// be tested somewhere that is not a Windows host with a flapping NIC. The
// callback needs no seam of its own: onRouteChange is a plain Go function, so
// calling it directly runs exactly the code Windows runs.
var (
	notifyRoute = func(callback uintptr, handle *windows.Handle) error {
		// AF_UNSPEC, not AF_INET followed by AF_INET6. MSDN's AddressFamily
		// table gives three legal values and defines this one as "Register for
		// both IPv4 and IPv6 route change notifications", so a single
		// registration covers both families and — the part that matters for
		// teardown — leaves exactly ONE handle to cancel. Two registrations
		// would mean two handles, two cancels, and a half-cancelled state to
		// get wrong on the error path.
		//
		// Both families are genuinely wanted: netstate reads v4 and v6 default
		// routes alike, and a dual-stack or v6-only network whose v6 default
		// moved has moved, whatever v4 is doing.
		//
		// initialNotification is false. MSDN states its purpose outright — "to
		// provide confirmation that the callback is registered" — which is
		// what this call's own NO_ERROR return already reports, and states
		// just as plainly that the notification it produces "does not indicate
		// a change occurred to an IP route entry". Forwarding that would hand
		// the watcher a routing change the kernel never reported, and buy a
		// facts collection, a re-verify and a portal probe with it, on every
		// start and on every retry after a failure.
		//
		// The third argument is the literal nil discussed on activeReg: this
		// process hands Windows no pointer to hold.
		return windows.NotifyRouteChange2(windows.AF_UNSPEC, callback, nil, false, handle)
	}

	// cancelRoute is x/sys' own CancelMibChangeNotify2, NOT a wrapper.
	//
	// Plan 4's brief expected this procedure to be missing from x/sys and to
	// need a NewLazySystemDLL wrapper in the style of
	// internal/sysconf/scwindows/iphlp.go. It is present. Verified by reading
	// golang.org/x/sys@v0.43.0/windows/syscall_windows.go (the //sys line
	// declaring it against iphlpapi) and zsyscall_windows.go (the generated
	// body: a real syscall.SyscallN through a NewProc, with `if r0 != 0 {
	// errcode = syscall.Errno(r0) }`). That is the iphlpapi convention
	// scwindows documents — the return value IS the Win32 code, NO_ERROR is
	// zero, and there is nothing to fetch from GetLastError — already applied
	// correctly, so a wrapper here would add a hand-written copy of a
	// generated one and a second place for the convention to drift.
	cancelRoute = windows.CancelMibChangeNotify2
)

// Run registers for route-change notifications and forwards them until ctx is
// done.
//
// The shape is the inverse of route_darwin.go's and is simpler for it. There
// the goroutine parks inside a blocking read and cancellation works by closing
// the socket underneath it; here Windows pushes, so this loop only ever waits
// on two Go channels. "Returns promptly once ctx is done" is therefore
// structural rather than argued: the loop is never inside a syscall, so there
// is nothing to interrupt.
func (s *RouteSource) Run(ctx context.Context, out chan<- struct{}) error {
	reg := &routeReg{signal: make(chan struct{}, 1)}
	if !activeReg.CompareAndSwap(nil, reg) {
		return ErrRouteSourceBusy
	}
	// Retracted LAST — defers run LIFO, so the deregistration below goes
	// first. While the registration is live the callback may still fire, and
	// it must find a channel to drop a signal into rather than a nil this
	// goroutine has already cleared. Compare-and-swap rather than Store(nil)
	// because it retracts only our own publication and can never clobber a
	// successor's.
	defer activeReg.CompareAndSwap(reg, nil)

	var h windows.Handle
	if err := notifyRoute(routeChangeCallback, &h); err != nil {
		// Returned rather than swallowed, so Watcher.startSource emits a
		// KindError the user can see and retries. A source that failed to
		// register and said nothing would leave the watcher running on the
		// sleep ticker alone while the wiring still claimed dpb was watching
		// the network.
		return fmt.Errorf("netwatch: register for route-change notifications: %w", err)
	}

	defer func() {
		// MSDN: "Once the NotifyRouteChange2 function is called to register
		// for change notifications, these notifications will continue to be
		// sent until the application deregisters for change notifications or
		// the application terminates", and deregistering explicitly before
		// terminating is recommended even so. The sharper reason is local: a
		// callback that fired after Run returned would be firing into a torn
		// down world.
		//
		// This runs on Run's own goroutine, after the loop below has exited.
		// Never from inside the callback, which MSDN says deadlocks outright —
		// "An application cannot make a call to the CancelMibChangeNotify2
		// function from the context of the thread which is currently executing
		// the notification callback function for the same NotificationHandle
		// parameter" — and never while holding anything the callback waits on,
		// because the callback waits on nothing at all.
		//
		// A failed cancel is logged, not returned. Run's error is the
		// watcher's retry signal, and "the notifications stopped and could not
		// be tidied up" is not a reason to report the source as broken when
		// ctx cancellation is what brought us here.
		//
		// This is also where a NULL handle would surface. MSDN says one is
		// returned only on error — "On success, a notification handle is
		// returned in this parameter. If an error occurs, NULL is returned" —
		// so NO_ERROR with h == 0 would be Windows breaking its own contract,
		// and the cancel below would report ERROR_INVALID_PARAMETER for it.
		// Run deliberately does NOT treat that as fatal: returning an error
		// would send Watcher.startSource round its retry loop, leaking one
		// more registration nobody can cancel every SourceRetry, which is
		// strictly worse than one leak and a log line saying so.
		if err := cancelRoute(h); err != nil {
			s.logf("netwatch: deregistering route-change notifications failed: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-reg.signal:
			s.logf("netwatch: a route-change notification arrived")
			// Coalesce, for route_darwin.go's reason: the watcher debounces
			// anyway, and a full channel means a signal it has not yet acted
			// on, so one more adds nothing and blocking here would wedge the
			// only goroutine that can drain the callback's channel.
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}
}
