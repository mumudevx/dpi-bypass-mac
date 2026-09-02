package flow

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSafeRunsFn(t *testing.T) {
	done := make(chan struct{})
	Safe("worker", nil, func() { close(done) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Safe never ran fn")
	}
}

// A panic in a connection goroutine must kill that connection only. If Safe
// let it escape, the test binary itself would die, so surviving this test is
// the assertion.
func TestSafeContainsPanicAndReportsIt(t *testing.T) {
	before := PanicCount()

	var mu sync.Mutex
	var logged string

	done := make(chan struct{})
	prev := SetPanicHook(func(name string, v any, stack []byte) {
		mu.Lock()
		defer mu.Unlock()
		if name != "conn-42" {
			t.Errorf("OnPanic name = %q, want conn-42", name)
		}
		if v != "boom" {
			t.Errorf("OnPanic value = %v, want boom", v)
		}
		if !strings.Contains(string(stack), "flow.Safe") {
			t.Errorf("stack does not name the panicking goroutine:\n%s", stack)
		}
		close(done)
	})
	t.Cleanup(func() { SetPanicHook(prev) })

	Safe("conn-42", func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = format
		_ = args
	}, func() { panic("boom") })

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnPanic was never called")
	}

	mu.Lock()
	got := logged
	mu.Unlock()
	if !strings.Contains(got, "panic in %s") {
		t.Errorf("logf format = %q, want it to name the goroutine", got)
	}
	if PanicCount() != before+1 {
		t.Errorf("PanicCount = %d, want %d", PanicCount(), before+1)
	}
}

// A hook that panics must not defeat the containment it was installed to
// observe.
func TestSafeSurvivesAPanickingHook(t *testing.T) {
	entered := make(chan struct{})
	prev := SetPanicHook(func(string, any, []byte) {
		close(entered)
		panic("hook exploded")
	})
	t.Cleanup(func() { SetPanicHook(prev) })

	Safe("conn-hook", nil, func() { panic("original") })

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("hook was never entered")
	}
	// Give the recovering goroutine a chance to finish unwinding before the
	// test binary moves on; if containment failed the process is already gone.
	time.Sleep(50 * time.Millisecond)
}

// A nil logf must not itself panic — callers that have not built a logger yet
// still need containment.
func TestSafeToleratesNilLogf(t *testing.T) {
	prev := SetPanicHook(nil)
	t.Cleanup(func() { SetPanicHook(prev) })

	before := PanicCount()
	Safe("conn-nil", nil, func() { panic("quiet") })

	deadline := time.Now().Add(2 * time.Second)
	for PanicCount() == before {
		if time.Now().After(deadline) {
			t.Fatal("panic was never recovered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
