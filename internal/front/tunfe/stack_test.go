package tunfe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/policy"
)

// TestBringUpOrdering pins docs/PLAN.md data path F. The order is not a
// preference:
//
//   - the interface must carry an address before any route names it;
//   - the scoped default must exist before the capture routes, or our own
//     upstream sockets are pulled back into the tunnel we just installed;
//   - the datapath must be listening before the capture routes exist, or the
//     window between them is a blackhole;
//   - the nameserver host routes come last among the routes, because they only
//     matter once the tunnel is carrying traffic.
func TestBringUpOrdering(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	started := -1
	c := testCapture()

	err := c.BringUp(context.Background(), seq, func(context.Context) error {
		started = len(seq.ids())
		return nil
	})
	if err != nil {
		t.Fatalf("BringUp: %v", err)
	}

	want := []string{
		"ifconfig:utun7/10.6.6.1",
		"route:0.0.0.0/0@en0",
		"route:0.0.0.0/1@utun7",
		"route:128.0.0.0/1@utun7",
		"route:192.168.1.1/32@utun7",
		"dns.servers:Wi-Fi",
	}
	got := seq.ids()
	if len(got) != len(want) {
		t.Fatalf("applied %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d = %q, want %q (full order %v)", i, got[i], want[i], got)
		}
	}
	if started != 2 {
		t.Fatalf("the datapath started after %d Op(s), want 2: it must be listening before the "+
			"capture routes exist and after the scoped default that lets our own sockets out", started)
	}
}

// TestBringUpStopsAtTheFirstFailure: each step is verified before the next is
// attempted, so a failure leaves nothing after it applied. netstate rolls the
// failed Op back itself; what this pins is that BringUp does not carry on.
func TestBringUpStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()
	for _, step := range []int{0, 1, 2, 4} {
		t.Run(fmt.Sprintf("step%d", step), func(t *testing.T) {
			seq := &recordingSequencer{failAt: step, failErr: errors.New("route: writing to routing socket")}
			started := false
			err := testCapture().BringUp(context.Background(), seq, func(context.Context) error {
				started = true
				return nil
			})
			if err == nil {
				t.Fatal("BringUp reported success after a step failed")
			}
			if n := len(seq.ids()); n != step+1 {
				t.Fatalf("%d Op(s) attempted, want %d: the sequence continued past a failure", n, step+1)
			}
			if step < 2 && started {
				t.Fatal("the datapath was started even though bring-up had already failed")
			}
		})
	}
}

// TestBringUpFailsWhenTheDatapathDoesNotStart: if the netstack cannot come up,
// the capture routes must never be installed. Installing them anyway is the
// blackhole this ordering exists to prevent.
func TestBringUpFailsWhenTheDatapathDoesNotStart(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	boom := errors.New("netstack refused to start")
	err := testCapture().BringUp(context.Background(), seq, func(context.Context) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("BringUp = %v, want it to wrap %v", err, boom)
	}
	for _, id := range seq.ids() {
		if strings.Contains(id, "utun7") && strings.HasPrefix(id, "route:") {
			t.Fatalf("capture route %q was installed even though the datapath never started", id)
		}
	}
}

// TestTearDownRevertsBeforeClosingTheDevice is the ordering that actually
// matters at shutdown: macOS `route delete` naming a closed interface fails —
// and route(8) reports that failure with exit status 0, so nothing downstream
// would notice. The device is therefore closed last, after every route naming
// it is gone.
func TestTearDownRevertsBeforeClosingTheDevice(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	c := testCapture()
	if err := c.BringUp(context.Background(), seq, nil); err != nil {
		t.Fatalf("BringUp: %v", err)
	}

	link, _ := NewPipe(0)
	var order []string
	stop := func() { order = append(order, "stop") }
	seq.onUndo = func() { order = append(order, "undo") }

	if errs := c.TearDown(context.Background(), seq, stop, link); len(errs) != 0 {
		t.Fatalf("TearDown: %v", errs)
	}
	order = append(order, "closed")
	if _, err := link.Name(); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("the device was not closed: %v", err)
	}
	want := []string{"undo", "stop", "closed"}
	for i := range want {
		if i >= len(order) || order[i] != want[i] {
			t.Fatalf("teardown order = %v, want %v", order, want)
		}
	}
	if !seq.undone {
		t.Fatal("UndoAll was never called; the journalled state would be left applied")
	}
}

// TestTearDownReportsACloseFailure: a device that will not close is reported,
// not swallowed, because the journal entry for the interface has already been
// closed by then.
func TestTearDownReportsACloseFailure(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{undoErrs: []error{errors.New("route delete failed")}}
	errs := testCapture().TearDown(context.Background(), seq, nil, newFailingLink())
	if len(errs) != 2 {
		t.Fatalf("TearDown returned %v, want both the revert failure and the close failure", errs)
	}
}

// TestBringUpValidatesItsInputs: an Op built from a missing device name or
// address would be applied to whatever ifconfig makes of an empty string.
func TestBringUpValidatesItsInputs(t *testing.T) {
	t.Parallel()
	seq := &recordingSequencer{}
	if err := (Capture{}).BringUp(context.Background(), seq, nil); err == nil {
		t.Fatal("BringUp accepted a Capture with no interface")
	}
	if err := (Capture{Iface: "utun7"}).BringUp(context.Background(), seq, nil); err == nil {
		t.Fatal("BringUp accepted a Capture with no tunnel address")
	}
	c := testCapture()
	if err := c.BringUp(context.Background(), nil, nil); err == nil {
		t.Fatal("BringUp accepted a nil sequencer")
	}
	if n := len(seq.ids()); n != 0 {
		t.Fatalf("%d Op(s) were applied for an invalid Capture", n)
	}
}

// TestBringUpRejectsAnUnusableNameserver: a nameserver that is not an address
// cannot become a host route, and inventing one would capture the wrong prefix.
func TestBringUpRejectsAnUnusableNameserver(t *testing.T) {
	t.Parallel()
	c := testCapture()
	c.Nameservers = []netip.Addr{{}}
	if err := c.BringUp(context.Background(), &recordingSequencer{}, nil); err == nil {
		t.Fatal("BringUp accepted an invalid nameserver")
	}
}

// TestCaptureRoutesAreTheTwoHalves: the halves are used rather than a default
// route so the machine's own default survives underneath, which is what lets
// our upstream sockets escape by binding to the uplink.
func TestCaptureRoutesAreTheTwoHalves(t *testing.T) {
	t.Parallel()
	got := CaptureRoutes()
	want := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if len(got) != len(want) {
		t.Fatalf("CaptureRoutes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("CaptureRoutes = %v, want %v", got, want)
		}
	}
}

// TestNewValidatesWiring: a Server missing its engine or its scope would relay
// every captured flow unjudged, so it must fail at construction rather than at
// the first connection.
func TestNewValidatesWiring(t *testing.T) {
	t.Parallel()
	a, _ := NewPipe(0)
	scope := policy.NewEngine(policy.EngineOptions{})
	runner := &flow.LadderRunner{Dial: &upstreamDialer{}}

	if _, err := New(Options{Scope: scope, Ladder: runner}); !errors.Is(err, ErrNoLink) {
		t.Fatalf("New with no link = %v, want ErrNoLink", err)
	}
	if _, err := New(Options{Link: a, Scope: scope}); !errors.Is(err, ErrNoLadder) {
		t.Fatalf("New with no ladder = %v, want ErrNoLadder", err)
	}
	if _, err := New(Options{Link: a, Ladder: runner}); !errors.Is(err, ErrNoScope) {
		t.Fatalf("New with no scope = %v, want ErrNoScope", err)
	}
	if _, err := New(Options{Link: a, Scope: scope, Ladder: &flow.LadderRunner{}}); err == nil {
		t.Fatal("New accepted a runner with no dialer")
	}

	srv, err := New(Options{Link: a, Scope: scope, Ladder: runner})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()
	// The MTU comes from the device when the caller did not set one.
	if got := srv.o.MTU; got != DefaultMTU {
		t.Fatalf("MTU = %d, want the device's %d", got, DefaultMTU)
	}
	if srv.o.Dial == nil {
		t.Fatal("the direct path was left with no dialer")
	}
	srv.Close() // idempotent
}

// TestServeDrainsDeviceEvents: the real device feeds its event channel from a
// route-socket reader over a buffer of ten, and that reader wedges permanently
// once nobody is listening — after which no interface event is ever seen again.
func TestServeDrainsDeviceEvents(t *testing.T) {
	l := newLab(t, labOpts{})
	for i := 0; i < 20; i++ {
		l.serverLink.Emit(EventUp)
	}
	waitFor(t, 5*time.Second, "the event channel to drain", func() bool {
		return len(l.serverLink.Events()) == 0
	})
}

// recordingSequencer stands in for *netstate.Manager. It records the Ops in the
// order they were applied, and can fail at a chosen step.
type recordingSequencer struct {
	mu       sync.Mutex
	applied  []netstate.Op
	failAt   int
	failErr  error
	undone   bool
	undoErrs []error
	onUndo   func()
}

func (s *recordingSequencer) Do(_ context.Context, op netstate.Op) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.applied)
	s.applied = append(s.applied, op)
	if s.failErr != nil && n == s.failAt {
		return s.failErr
	}
	return nil
}

func (s *recordingSequencer) UndoAll(context.Context) []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.undone = true
	if s.onUndo != nil {
		s.onUndo()
	}
	return s.undoErrs
}

func (s *recordingSequencer) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.applied))
	for _, op := range s.applied {
		out = append(out, op.ID())
	}
	return out
}

// testCapture is the shipped shape of a bring-up: a utun, a scoped default via
// the uplink, the two capture halves, one on-subnet nameserver and the DNS
// switch.
func testCapture() Capture {
	return Capture{
		Iface:       "utun7",
		Local:       netip.MustParseAddr("10.6.6.1"),
		Peer:        netip.MustParseAddr("10.6.6.2"),
		MTU:         DefaultMTU,
		Uplink:      "en0",
		Gateway:     netip.MustParseAddr("192.168.1.1"),
		Nameservers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		Resolvers:   []string{"10.6.6.1"},
		Services:    []string{"Wi-Fi"},
	}
}

// failingLink is a Link whose Close fails, so the teardown's error reporting is
// testable.
type failingLink struct{ *PipeLink }

func (failingLink) Close() error { return errors.New("device is stuck") }

func newFailingLink() failingLink {
	a, _ := NewPipe(0)
	return failingLink{PipeLink: a}
}
