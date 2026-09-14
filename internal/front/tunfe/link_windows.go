//go:build windows

package tunfe

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// defaultAdapterName is what OpenDevice calls the adapter when the caller
// leaves name empty.
//
// A wintun adapter takes a friendly name — what Windows shows in Network
// Connections — not a kernel-assigned unit like darwin's utunN: there is no
// unit for a kernel to pick, so a fixed name is wintun's equivalent of
// darwin's bare "utun". wintun.CreateAdapter also reuses an existing adapter
// of the same name rather than erroring, so an adapter left behind by a killed
// dpb process is picked back up on the next run instead of a new one
// accumulating every time.
const defaultAdapterName = "dpb"

// OpenDevice opens a wintun adapter.
//
// name must be a name wintun will accept as an adapter name; "" means
// defaultAdapterName. mtu <= 0 means DefaultMTU.
//
// Unlike darwin's utun, Name() does not report something the OS assigned:
// wireguard/tun's NativeTun.Name (tun_windows.go) just echoes back the ifname
// CreateTUN was called with, so on Windows, today, the returned Link's Name()
// reports exactly the name that was requested.
//
// Every route and interface Op downstream still reads it from Name() rather
// than assuming this, because "ask the device, never the request" is Link's
// invariant, not one platform's — see link_darwin.go, where the kernel really
// does substitute a different name, and where relying on the request instead
// would configure an interface that does not exist.
func OpenDevice(name string, mtu int, logf func(string, ...any)) (Link, error) {
	if name == "" {
		name = defaultAdapterName
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		// CreateTUN loads wintun.dll on first use (wireguard/tun's
		// tun_windows.go, via golang.zx2c4.com/wintun's lazyDLL). Absent the
		// DLL, LoadLibraryEx fails with one of these two well-known Win32
		// codes, wrapped twice on the way back up to us — a user reading
		// "Error loading Wintun DLL: Unable to load library: The specified
		// module could not be found." has no reason to know that means "the
		// wintun driver isn't installed," so say that plainly instead of
		// leaving them to decode the wrapped error on its own. The original
		// is kept via %w for whoever does want it.
		if errors.Is(err, windows.ERROR_MOD_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, fmt.Errorf("tunfe: create %s: the wintun driver is not installed (wintun.dll was not found): %w", name, err)
		}
		return nil, fmt.Errorf("tunfe: create %s: %w", name, err)
	}
	return newDeviceLink(dev, logf), nil
}
