package netwatch

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// rtmsg builds a routing message header: u_short rtm_msglen, u_char
// rtm_version, u_char rtm_type, then a body we do not parse.
func rtmsg(typ byte, version byte, body int) []byte {
	b := make([]byte, 4+body)
	binary.NativeEndian.PutUint16(b[:2], uint16(len(b)))
	b[2] = version
	b[3] = typ
	return b
}

func TestMessageType(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want byte
		ok   bool
	}{
		{name: "an RTM_ADD", in: rtmsg(rtmAdd, unix.RTM_VERSION, 60), want: rtmAdd, ok: true},
		{name: "an RTM_IFINFO2", in: rtmsg(rtmIfInfo2, unix.RTM_VERSION, 100), want: rtmIfInfo2, ok: true},
		{name: "too short to hold a header", in: []byte{1, 2, 3}},
		{name: "empty"},
		{
			// A kernel whose routing messages we do not understand must not be
			// turned into a revalidation loop.
			name: "a version we do not speak",
			in:   rtmsg(rtmAdd, unix.RTM_VERSION+1, 60),
		},
		{
			name: "a length longer than the bytes actually read",
			in:   func() []byte { b := rtmsg(rtmAdd, unix.RTM_VERSION, 60); return b[:20] }(),
		},
		{
			name: "a nonsensical length",
			in: func() []byte {
				b := rtmsg(rtmAdd, unix.RTM_VERSION, 60)
				binary.NativeEndian.PutUint16(b[:2], 2)
				return b
			}(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := messageType(tc.in)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Fatalf("messageType = (0x%x, %v), want (0x%x, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestRouteSourceFiltersUninterestingMessages is the reason the filter exists:
// RTM_MISS fires on ordinary traffic to an unreachable address, constantly, on
// a laptop with a half-configured network. Waking the watcher for each one
// would cost a facts collection, three scutil invocations and a portal probe.
func TestRouteSourceFiltersUninterestingMessages(t *testing.T) {
	const rtmMiss = 0x7
	if interestingTypes[rtmMiss] {
		t.Fatal("RTM_MISS is in the interesting set; ordinary unreachable traffic will thrash the watcher")
	}
	for _, want := range []byte{rtmAdd, rtmDelete, rtmChange, rtmIfInfo, rtmNewAddr, rtmDelAddr, rtmIfInfo2} {
		if !interestingTypes[want] {
			t.Errorf("message type 0x%x is not in the interesting set", want)
		}
	}
}

// withPipeSource replaces the routing socket with an os.Pipe so the read loop
// can be driven with synthesised messages.
func withPipeSource(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prev := openRoute
	openRoute = func() (*os.File, error) { return r, nil }
	t.Cleanup(func() {
		openRoute = prev
		_ = w.Close()
	})
	return w
}

func TestRouteSourceSignalsOnlyInterestingMessages(t *testing.T) {
	w := withPipeSource(t)
	src := &RouteSource{Logf: t.Logf}
	out := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()

	if _, err := w.Write(rtmsg(0x7 /* RTM_MISS */, unix.RTM_VERSION, 40)); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-out:
		t.Fatal("an RTM_MISS woke the watcher")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := w.Write(rtmsg(rtmAdd, unix.RTM_VERSION, 40)); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-out:
	case <-time.After(3 * time.Second):
		t.Fatal("an RTM_ADD did not wake the watcher")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancellation; the blocking read was never interrupted")
	}
}

// TestRouteSourceCoalesces pins that a burst cannot block the reader. The
// kernel's socket buffer fills while we are stalled, and a routing message
// dropped by the kernel is one nobody ever sees.
func TestRouteSourceCoalesces(t *testing.T) {
	w := withPipeSource(t)
	src := &RouteSource{}
	out := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()

	for i := 0; i < 20; i++ {
		if _, err := w.Write(rtmsg(rtmAdd, unix.RTM_VERSION, 40)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	select {
	case <-out:
	case <-time.After(3 * time.Second):
		t.Fatal("no signal arrived")
	}
	cancel()
	<-done
}

// TestRouteSourceReportsAFailedOpen: losing the socket must be reported so the
// watcher can retry, not swallowed into a reader that never delivers.
func TestRouteSourceReportsAFailedOpen(t *testing.T) {
	prev := openRoute
	want := errors.New("operation not permitted")
	openRoute = func() (*os.File, error) { return nil, want }
	t.Cleanup(func() { openRoute = prev })

	err := (&RouteSource{}).Run(context.Background(), make(chan struct{}, 1))
	if !errors.Is(err, want) {
		t.Fatalf("Run = %v, want %v", err, want)
	}
}

// TestRouteSourceCustomTypes covers the Types override.
func TestRouteSourceCustomTypes(t *testing.T) {
	s := &RouteSource{Types: map[byte]bool{0x7: true}}
	if !s.types()[0x7] || s.types()[rtmAdd] {
		t.Fatal("the Types override was ignored")
	}
	if (&RouteSource{}).types()[0x7] {
		t.Fatal("the default set includes RTM_MISS")
	}
}

// TestLiveRoutingSocketOpensUnprivileged is the acceptance criterion for this
// file: the PF_ROUTE socket must be readable as an ordinary user, because the
// proxy front end runs without sudo and still has to notice that the network
// moved. It only opens and closes the socket; it mutates nothing.
func TestLiveRoutingSocketOpensUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this asserts the UNPRIVILEGED case; re-run without sudo")
	}
	f, err := openRouteSocket()
	if err != nil {
		t.Fatalf("open the routing socket as uid %d: %v", os.Geteuid(), err)
	}
	t.Logf("opened %s as uid %d", f.Name(), os.Geteuid())
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestLiveRouteSourceStopsPromptly runs the shipped source against the real
// kernel socket and asserts that cancelling the context returns within a
// second. A reader that could not be interrupted would park a goroutine on a
// socket for the life of the process and stall every teardown.
func TestLiveRouteSourceStopsPromptly(t *testing.T) {
	src := NewRouteSource()
	src.Logf = t.Logf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, make(chan struct{}, 1)) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil on cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the routing-socket reader did not stop within 2 s of cancellation")
	}
}

// TestDefaultSourceIsTheRoutingSocket pins that a Watcher built with no Source
// gets the real one rather than silently watching nothing.
func TestDefaultSourceIsTheRoutingSocket(t *testing.T) {
	if _, ok := newDefaultSource().(*RouteSource); !ok {
		t.Fatalf("newDefaultSource returned %T, want *RouteSource", newDefaultSource())
	}
}
