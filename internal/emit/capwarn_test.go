package emit

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/strategy"
)

// captureCapWarn redirects the withheld-capability notice into a buffer and
// clears the once-per-family guard, restoring both afterwards.
func captureCapWarn(t *testing.T) *bytes.Buffer {
	t.Helper()
	origOut, origReader := capWarnOut, hopLimitFor
	t.Cleanup(func() {
		capWarnOut, hopLimitFor = origOut, origReader
		capWarned[0].Store(false)
		capWarned[1].Store(false)
	})
	var buf bytes.Buffer
	capWarnOut = &buf
	capWarned[0].Store(false)
	capWarned[1].Store(false)
	return &buf
}

// A capability that vanishes without a word is the failure stub_other.go's
// comment names: "A capability that is silently absent is how a strategy gets
// downgraded without anyone noticing." Both grant sites used to test
// `err == nil` and throw the error away, so on a machine whose throwaway socket
// answers something unusable, CapSockTTL and CapUDPTTL disappeared with no log
// line at all and every TTL rung of the ladder was skipped for the life of the
// process.
func TestAWithheldTTLCapabilityNamesItselfAndItsReason(t *testing.T) {
	buf := captureCapWarn(t)
	hopLimitFor = func(bool) (int, error) {
		return 0, errors.New("getsockopt reported 0")
	}

	ttl, caps := grantHopLimit(false)
	if caps != 0 || ttl != 0 {
		t.Fatalf("grantHopLimit granted %s with ttl %d despite an unreadable default", caps, ttl)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("the capability was withheld silently")
	}
	for _, want := range []string{
		strategy.CapSockTTL.String(),
		strategy.CapUDPTTL.String(),
		"IPv4",
		"getsockopt reported 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the notice does not mention %q:\n%s", want, out)
		}
	}
}

// The read is cached in a sync.Once, so its failure never changes. Reprinting
// it per connection would bury the one line that mattered; printing it per
// address family is what keeps both a v4-only and a v6 shortfall visible.
func TestTheWithheldNoticeIsOncePerAddressFamily(t *testing.T) {
	buf := captureCapWarn(t)
	hopLimitFor = func(bool) (int, error) { return 0, errors.New("no default") }

	for i := 0; i < 5; i++ {
		grantHopLimit(false)
	}
	if got := strings.Count(buf.String(), "IPv4"); got != 1 {
		t.Errorf("five withheld v4 grants printed %d notices, want 1", got)
	}

	grantHopLimit(true)
	if got := strings.Count(buf.String(), "IPv6"); got != 1 {
		t.Errorf("a withheld v6 grant printed %d notices, want 1", got)
	}
}

// defaultHopLimit is contracted to reject anything outside 1..255, so a zero
// with no error is a broken leaf rather than a machine fact. It must still be
// reported: this is the shape the Windows leaf would take if its range check
// were ever removed, and it is the one that cannot be seen from the error.
func TestAZeroHopLimitWithNoErrorIsStillReported(t *testing.T) {
	buf := captureCapWarn(t)
	hopLimitFor = func(bool) (int, error) { return 0, nil }

	if _, caps := grantHopLimit(false); caps != 0 {
		t.Fatalf("grantHopLimit granted %s for a hop limit of 0", caps)
	}
	if !strings.Contains(buf.String(), "want 1..255") {
		t.Errorf("the notice does not say what was wrong with the value:\n%s", buf.String())
	}
}

// The happy path stays quiet, and stays a grant. This machine can read its own
// default hop limit, so a notice here would mean the guard fires on healthy
// runs — noise that trains the reader to ignore the real one.
func TestAGrantedTTLCapabilityIsSilent(t *testing.T) {
	buf := captureCapWarn(t)

	ttl, caps := grantHopLimit(false)
	if !caps.Has(strategy.CapSockTTL) || !caps.Has(strategy.CapUDPTTL) {
		t.Fatalf("grantHopLimit on this machine returned %s, want both TTL capabilities", caps)
	}
	if ttl < 1 || ttl > 255 {
		t.Fatalf("grantHopLimit returned a hop limit of %d", ttl)
	}
	if buf.String() != "" {
		t.Errorf("a successful grant printed a warning:\n%s", buf.String())
	}
}
