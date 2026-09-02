//go:build !darwin

package flow

import (
	"fmt"
	"runtime"
)

// bindToInterface refuses rather than silently leaving the socket unbound.
//
// dpb ships on darwin only. A silent no-op here would mean that on any other
// platform every upstream connection follows the default route — straight back
// into our own tunnel — and the failure would present as an unexplained hang
// rather than as a missing feature.
func bindToInterface(_ uintptr, name string, _ bool) error {
	return fmt.Errorf("binding a socket to %q is implemented on darwin only, not %s", name, runtime.GOOS)
}
