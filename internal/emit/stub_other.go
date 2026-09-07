//go:build !darwin

package emit

import (
	"fmt"
	"runtime"
	"syscall"

	"github.com/mumudevx/dpb/internal/strategy"
)

// dpb ships for darwin only. This file exists so `GOOS=linux go build ./...` and
// a cross-platform editor still work, and — more importantly — so the withheld
// capabilities carry a REASON. A capability that is silently absent is how a
// strategy gets downgraded without anyone noticing; every error below names the
// technique, the platform and the fact that the two do not meet here.
const (
	sockTTLCaps strategy.Cap = 0
	oobCaps     strategy.Cap = 0
)

func reason(what string) string {
	return fmt.Sprintf("%s is implemented for darwin only; this binary is %s/%s",
		what, runtime.GOOS, runtime.GOARCH)
}

// DefaultTTL has no portable source outside darwin's net.inet.ip.ttl, and
// guessing 64 is exactly the shortcut DOSSIER §3 warns against. Returning an
// error here is what withholds CapSockTTL in NewSockTransport.
func DefaultTTL() (int, error) {
	return 0, fmt.Errorf("%w: %s", ErrCapUnavailable, reason("reading the kernel default TTL"))
}

func defaultHopLimit(bool) (int, error) { return DefaultTTL() }

func setHopLimit(syscall.RawConn, bool, int) error {
	return fmt.Errorf("%w: %s", ErrCapUnavailable, reason("per-segment IP_TTL"))
}

func getHopLimit(syscall.RawConn, bool) (int, error) {
	return 0, fmt.Errorf("%w: %s", ErrCapUnavailable, reason("per-segment IP_TTL"))
}

func sendOOB(syscall.RawConn, []byte) (int, error) {
	return 0, fmt.Errorf("%w: %s", ErrCapUnavailable, reason("MSG_OOB urgent-byte injection"))
}
