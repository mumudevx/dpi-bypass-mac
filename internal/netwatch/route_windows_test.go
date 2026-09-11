//go:build windows

package netwatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// These tests cannot trigger a real routing change, and — like every other
// windows-tagged test in this tree — cannot be executed from the darwin host
// this was written on. `GOOS=windows go vet ./internal/netwatch/` compiles
// them and `GOOS=windows go test -c` links them; neither runs an assertion.
// internal/sysconf/scwindows/iphlp_test.go says the same about itself, and the
// Makefile's cover-gate says it a third time for the whole scwindows package.
//
// What they DO cover is everything in route_windows.go that is not a syscall:
// the two seams are swapped for recorders, and onRouteChange is called
// directly, which runs exactly the code Windows runs on its thread pool thread
// because it is an ordinary Go function.
//
// None of them may call t.Parallel(). They share route_windows.go's package
// level singleton and its two seams, which is the point of several of them.

// fakeNotify records the two IP Helper calls Run makes.
type fakeNotify struct {
	handle    windows.Handle
	notifyErr error
	cancelErr error

	mu sync.Mutex
	// callbacks is one entry per registration, holding the callback pointer
	// that registration was given. Every entry should be the same value.
	callbacks []uintptr
	cancels   []windows.Handle
	// regLiveAtCancel records whether the singleton was still published when
	// cancel ran. It must be true: deregistering has to come before retracting
	// the registration, or a callback already in flight finds nothing to drop
	// its signal into.
	regLiveAtCancel []bool
}

func (f *fakeNotify) notify(callback uintptr, handle *windows.Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callbacks = append(f.callbacks, callback)
	if f.notifyErr != nil {
		return f.notifyErr
	}
	*handle = f.handle
	return nil
}

func (f *fakeNotify) cancel(handle windows.Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancels = append(f.cancels, handle)
	f.regLiveAtCancel = append(f.regLiveAtCancel, activeReg.Load() != nil)
	return f.cancelErr
}

func (f *fakeNotify) snapshot() ([]uintptr, []windows.Handle, []bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uintptr(nil), f.callbacks...),
		append([]windows.Handle(nil), f.cancels...),
		append([]bool(nil), f.regLiveAtCancel...)
}

// installFakeNotify swaps the seams and restores them afterwards.
func installFakeNotify(t *testing.T, f *fakeNotify) {
	t.Helper()
	prevNotify, prevCancel := notifyRoute, cancelRoute
	notifyRoute, cancelRoute = f.notify, f.cancel
	t.Cleanup(func() { notifyRoute, cancelRoute = prevNotify, prevCancel })
}

// waitForRegistration blocks until Run has published (or retracted) the
// singleton. Polling beats a sleep: Run publishes before it registers, so the
// wait is over in microseconds on a healthy build and only the failure path
// pays the deadline.
func waitForRegistration(t *testing.T, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if (activeReg.Load() != nil) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the route-change registration was not %v within 3 s", want)
}

// runInBackground starts src and registers the cleanup that stops it. Every
// test that starts a Run must stop it before the seams are restored, or the
// singleton stays claimed and the next test fails with ErrRouteSourceBusy for
// a reason that has nothing to do with it.
//
// Cleanups run LIFO, so calling this after installFakeNotify is what
// guarantees the Run goroutine is finished before the seams are put back —
// otherwise the restore would race the goroutine still reading them.
func runInBackground(t *testing.T, src *RouteSource, out chan<- struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v, want nil on cancellation", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Run did not return within 3 s of cancellation")
		}
	})
}

// TestRouteSourceDeliversACallbackSignal is the first of the two contract
// properties: what the kernel pushes into the callback comes out on out.
//
// Without it the watcher would be wired to a source that registers
// successfully and never delivers — which is not a hypothetical failure mode
// in this tree but the shape of every Windows defect it has found so far: an
// API that compiles, looks right, and reports nothing true.
func TestRouteSourceDeliversACallbackSignal(t *testing.T) {
	f := &fakeNotify{handle: 0xABCD}
	installFakeNotify(t, f)

	out := make(chan struct{}, 4)
	runInBackground(t, &RouteSource{Logf: t.Logf}, out)
	waitForRegistration(t, true)

	// This is the call Windows makes on its thread pool thread. MibAddInstance
	// is the notification type a new route produces; the callback ignores it,
	// and it is passed anyway so the call is shaped like the real one.
	if r := onRouteChange(0, 0, windows.MibAddInstance); r != 0 {
		t.Fatalf("onRouteChange returned %d, want 0 (the C prototype is VOID)", r)
	}

	select {
	case <-out:
	case <-time.After(3 * time.Second):
		t.Fatal("a route-change callback never reached out; the watcher would run blind on the sleep ticker")
	}
}

// TestRouteSourceStopsPromptlyOnCancel is the second contract property. The
// watcher's own Run defers `scancel(); <-srcDone`, so a source that did not
// return would stall every teardown behind it.
func TestRouteSourceStopsPromptlyOnCancel(t *testing.T) {
	f := &fakeNotify{handle: 0x1}
	installFakeNotify(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&RouteSource{Logf: t.Logf}).Run(ctx, make(chan struct{}, 1)) }()
	waitForRegistration(t, true)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil on cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2 s of cancellation")
	}
	waitForRegistration(t, false)
}

// TestRouteSourceDeregistersBeforeReturning pins the teardown MSDN asks for
// and the ORDER it has to happen in. Cancelling the notification handle must
// come first, while the singleton is still published, so that a callback
// already in flight has a live channel to drop into; retracting the singleton
// first would leave that window open for exactly as long as the cancel takes.
func TestRouteSourceDeregistersBeforeReturning(t *testing.T) {
	f := &fakeNotify{handle: 0xBEEF}
	installFakeNotify(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&RouteSource{Logf: t.Logf}).Run(ctx, make(chan struct{}, 1)) }()
	waitForRegistration(t, true)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}

	_, cancels, live := f.snapshot()
	if len(cancels) != 1 {
		t.Fatalf("CancelMibChangeNotify2 was called %d times, want exactly 1; "+
			"an uncancelled handle lets the callback fire into a torn-down world", len(cancels))
	}
	if cancels[0] != f.handle {
		t.Errorf("cancelled handle %#x, want the one the registration returned (%#x)", cancels[0], f.handle)
	}
	if !live[0] {
		t.Error("the registration was retracted before the handle was cancelled; " +
			"an in-flight callback would have found no channel to signal on")
	}
	if activeReg.Load() != nil {
		t.Error("Run returned with the registration still published")
	}
}

// TestRouteSourceReportsAFailedRegistration: losing the registration must be
// reported so Watcher.startSource can emit a KindError and retry, not
// swallowed into a source that returns nil and never delivers.
func TestRouteSourceReportsAFailedRegistration(t *testing.T) {
	want := windows.ERROR_ACCESS_DENIED
	f := &fakeNotify{notifyErr: want}
	installFakeNotify(t, f)

	err := (&RouteSource{Logf: t.Logf}).Run(context.Background(), make(chan struct{}, 1))
	if !errors.Is(err, want) {
		t.Fatalf("Run = %v, want it to wrap %v", err, want)
	}
	if activeReg.Load() != nil {
		t.Fatal("a failed registration left the singleton claimed; every later Run would be refused")
	}
	if _, cancels, _ := f.snapshot(); len(cancels) != 0 {
		t.Errorf("a registration that never succeeded was cancelled anyway (%d times)", len(cancels))
	}
}

// TestRouteSourceRefusesASecondConcurrentRun pins the singleton invariant that
// makes a nil callerContext safe. A second Run must fail by name rather than
// register a second time and overwrite the first one's published state, which
// would leave the first watcher silently blind.
func TestRouteSourceRefusesASecondConcurrentRun(t *testing.T) {
	f := &fakeNotify{handle: 0x2}
	installFakeNotify(t, f)

	out := make(chan struct{}, 1)
	runInBackground(t, &RouteSource{Logf: t.Logf}, out)
	waitForRegistration(t, true)

	err := (&RouteSource{Logf: t.Logf}).Run(context.Background(), out)
	if !errors.Is(err, ErrRouteSourceBusy) {
		t.Fatalf("a second concurrent Run = %v, want ErrRouteSourceBusy", err)
	}
	callbacks, cancels, _ := f.snapshot()
	if len(callbacks) != 1 {
		t.Errorf("the refused Run registered anyway: %d registrations, want 1", len(callbacks))
	}
	if len(cancels) != 0 {
		t.Errorf("the refused Run cancelled the live registration's handle (%d cancels)", len(cancels))
	}
}

// TestRouteSourceReusesOneCompiledCallback is the budget constraint in
// syscall.NewCallback's own documentation: "Only a limited number of callbacks
// may be created in a single Go process, and any memory allocated for these
// callbacks is never released." Watcher.startSource re-runs a failed source
// once every SourceRetry forever, so a NewCallback per Run would eventually
// panic on a machine whose only fault was a flapping network.
func TestRouteSourceReusesOneCompiledCallback(t *testing.T) {
	if routeChangeCallback == 0 {
		t.Fatal("routeChangeCallback is 0; syscall.NewCallback produced no code address")
	}
	f := &fakeNotify{handle: 0x3}
	installFakeNotify(t, f)

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- (&RouteSource{}).Run(ctx, make(chan struct{}, 1)) }()
		waitForRegistration(t, true)
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		waitForRegistration(t, false)
	}

	callbacks, _, _ := f.snapshot()
	if len(callbacks) != 3 {
		t.Fatalf("registered %d times across 3 runs, want 3", len(callbacks))
	}
	for i, c := range callbacks {
		if c != routeChangeCallback {
			t.Errorf("run %d registered callback %#x, want the package-level %#x", i, c, routeChangeCallback)
		}
	}
}

// TestRouteSourceCoalesces pins that the callback can never block and that a
// burst cannot wedge the forwarder. MSDN: "The invocation of the callback
// function ... is serialized", so a callback that waited on a full channel
// would stall every notification queued behind it — on a Windows thread pool
// thread, where nothing in this process can recover.
func TestRouteSourceCoalesces(t *testing.T) {
	f := &fakeNotify{handle: 0x4}
	installFakeNotify(t, f)

	// Deliberately never drained, and deliberately the same capacity
	// Watcher.Run gives its raw channel.
	out := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&RouteSource{}).Run(ctx, out) }()
	waitForRegistration(t, true)

	fired := make(chan struct{})
	go func() {
		defer close(fired)
		for i := 0; i < 200; i++ {
			onRouteChange(0, 0, windows.MibParameterNotification)
		}
	}()
	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("the callback blocked; on a real thread pool thread this would stall every later notification")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the forwarder wedged on an undrained out channel")
	}
	if len(out) != 1 {
		t.Errorf("out holds %d signals, want exactly 1 coalesced", len(out))
	}
}

// TestOnRouteChangeWithNoLiveRegistration covers the window MSDN leaves open:
// a callback may be in flight while Run is tearing down. It must find the
// retracted singleton and return quietly rather than panic, because a panic
// there happens on a thread with none of this process's frames above it.
func TestOnRouteChangeWithNoLiveRegistration(t *testing.T) {
	if activeReg.Load() != nil {
		t.Fatal("a previous test leaked a registration")
	}
	if r := onRouteChange(0, 0, windows.MibDeleteInstance); r != 0 {
		t.Fatalf("onRouteChange returned %d, want 0", r)
	}
}

// TestDefaultSourceIsTheNotificationAPI pins that a Watcher built with no
// Source gets the real one. This is the assertion route_other.go's comment
// argues for: returning nil here would leave dpb "watching the network" in the
// wiring and not in fact.
func TestDefaultSourceIsTheNotificationAPI(t *testing.T) {
	if _, ok := newDefaultSource().(*RouteSource); !ok {
		t.Fatalf("newDefaultSource returned %T, want *RouteSource", newDefaultSource())
	}
}

// TestLiveRouteNotificationRegisters is the acceptance criterion for this
// file, and the only test here that touches the kernel. It registers for real
// route-change notifications, confirms a handle came back, and deregisters. It
// mutates nothing.
//
// It is the Windows counterpart of route_darwin.go's
// TestLiveRoutingSocketOpensUnprivileged, and it exists for the same reason
// internal/sysconf/scwindows/iphlp_test.go's procedure-resolution test does: a
// procedure that is absent, renamed, or refused on a supported Windows version
// would otherwise surface as a source that registers, returns nil, and never
// delivers — on a user's machine, silently. Nobody has run it.
func TestLiveRouteNotificationRegisters(t *testing.T) {
	var h windows.Handle
	if err := windows.NotifyRouteChange2(windows.AF_UNSPEC, routeChangeCallback, nil, false, &h); err != nil {
		t.Fatalf("NotifyRouteChange2(AF_UNSPEC): %v", err)
	}
	if h == 0 {
		// MSDN: "On success, a notification handle is returned in this
		// parameter. If an error occurs, NULL is returned." NO_ERROR with a
		// NULL handle would be the "could not query means definitely dead"
		// conflation in reverse, and there would be nothing to cancel.
		t.Fatal("NotifyRouteChange2 reported NO_ERROR but returned a NULL handle")
	}
	if err := windows.CancelMibChangeNotify2(h); err != nil {
		t.Fatalf("CancelMibChangeNotify2(%#x): %v", h, err)
	}
}
