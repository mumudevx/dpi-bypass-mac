package emit

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/mumudevx/dpb/internal/strategy"
)

// capWarnOut is where a withheld-capability notice goes. It is a var so a test
// can capture it; nil silences the notice, which no shipping path does.
//
// This package deliberately has no logger of its own and takes no dependency on
// internal/observ: emit sits under the per-connection hot path, and threading a
// logger through NewSockTransport and UDPCaps would change every caller on
// every platform to carry something that is used on one failure path. Stderr is
// where dpb's logger writes anyway.
var capWarnOut io.Writer = os.Stderr

// capWarned records whether the notice for an address family has already been
// printed: [0] is IPv4, [1] is IPv6.
//
// Once per family per process is exactly right rather than merely polite. The
// underlying read is cached in a sync.Once, so its failure is permanent for the
// life of the process; without this guard the same unchanging fact would be
// reprinted for every connection dpb makes, which is how the one line that
// mattered gets scrolled away.
var capWarned [2]atomic.Bool

// grantHopLimit resolves the kernel default hop limit for one address family
// and reports which capabilities that permits granting. A zero Cap means they
// are withheld, and the reason has already been written to capWarnOut.
//
// The notice is the point of this function. Both grant sites used to test
// `err == nil` and discard the error, so on a machine where the throwaway
// socket answers something unusable — 0, or a getsockopt that fails —
// CapSockTTL and CapUDPTTL vanished with NO output at all, and the strategy
// ladder silently dropped to a lower rung for the rest of the process. That is
// precisely the failure stub_other.go's comment says must never happen: "A
// capability that is silently absent is how a strategy gets downgraded without
// anyone noticing." A withheld capability must always carry a reason, whether
// the platform withholds it by construction or a machine withholds it at run
// time.
// hopLimitFor is the seam onto the per-platform read. It exists so a test can
// drive the failure this whole file is about without owning a machine whose
// kernel actually answers 0 — the case that, being cached in a sync.Once, is
// permanent for the process once it happens.
var hopLimitFor = defaultHopLimit

func grantHopLimit(v6 bool) (ttl int, caps strategy.Cap) {
	n, err := hopLimitFor(v6)
	if err == nil && n > 0 {
		return n, sockTTLCaps
	}
	if err == nil {
		// defaultHopLimit itself rejects anything outside 1..255, so reaching
		// here means it returned a zero with no error — a contract break rather
		// than a machine fact, and still not something to swallow.
		err = fmt.Errorf("emit: default hop limit read back as %d, want 1..255", n)
	}
	warnCapWithheld(v6, sockTTLCaps, err)
	return 0, 0
}

// warnCapWithheld names the capabilities being withheld, the address family,
// and why — once per family.
func warnCapWithheld(v6 bool, caps strategy.Cap, err error) {
	i := 0
	family := "IPv4"
	if v6 {
		i, family = 1, "IPv6"
	}
	if !capWarned[i].CompareAndSwap(false, true) {
		return
	}
	w := capWarnOut
	if w == nil {
		return
	}
	fmt.Fprintf(w, "dpb: withholding %s for %s: the kernel default hop limit is unreadable "+
		"on this machine (%v), and a TTL that cannot be restored afterwards would "+
		"black-hole the rest of the connection; every TTL rung of the strategy ladder "+
		"will be skipped for the life of this process\n", caps, family, err)
}
