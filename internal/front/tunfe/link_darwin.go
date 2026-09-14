//go:build darwin

package tunfe

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// OpenDevice opens a utun device. It is the one place in this package that
// needs root to exercise fully: it does nothing but call CreateTUN and hand
// the result to newDeviceLink (link.go), so the only thing left untested
// without root is this one syscall wrapper.
//
// name must be "utun" (the kernel picks a free unit) or "utunN". mtu <= 0 means
// DefaultMTU. The returned Link's Name() reports the device the kernel actually
// gave us, which is the name every route and ifconfig Op must be told — never
// the name that was requested.
func OpenDevice(name string, mtu int, logf func(string, ...any)) (Link, error) {
	if name == "" {
		name = "utun"
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunfe: create %s: %w", name, err)
	}
	return newDeviceLink(dev, logf), nil
}
