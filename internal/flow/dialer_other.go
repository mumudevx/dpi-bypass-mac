//go:build !darwin && !windows

package flow

import (
	"fmt"
	"runtime"
)

// bindToInterface refuses rather than silently leaving the socket unbound.
//
// darwin (IP_BOUND_IF, dialer_darwin.go) and windows (IP_UNICAST_IF /
// IPV6_UNICAST_IF, dialer_windows.go) each have a real pin. Every other OS
// lands here and still lacks one. A silent no-op here would mean that on
// those platforms every upstream connection follows the default route —
// straight back into our own tunnel in TUN mode — and the failure would
// present as an unexplained hang rather than as a missing feature.
func bindToInterface(_ uintptr, name string, _ bool) error {
	return fmt.Errorf("binding a socket to %q is implemented on darwin and windows only, not %s", name, runtime.GOOS)
}
