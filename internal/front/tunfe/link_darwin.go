//go:build darwin

package tunfe

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/mumudevx/dpb/internal/flow"
)

// The real device. This is the one file in the package that needs root to
// exercise fully, so it is kept as close to zero logic as it can be: OpenDevice
// is a wrapper around CreateTUN, and everything else is a translation of one
// value into another.
//
// deviceLink is written against the wgDevice interface rather than against
// *wgtun.NativeTun so that the translation itself — the part that could be
// wrong — is testable with a fake device and no root at all. What is left
// untested without root is exactly one syscall wrapper.

// wgDevice is the wireguard/tun contract, narrowed to what deviceLink uses.
type wgDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	MTU() (int, error)
	Name() (string, error)
	Events() <-chan wgtun.Event
	BatchSize() int
	Close() error
}

var _ wgDevice = (wgtun.Device)(nil)

// deviceLink adapts a wireguard/tun device to Link.
type deviceLink struct {
	dev    wgDevice
	events chan Event
}

var _ Link = (*deviceLink)(nil)

// OpenDevice opens a utun device.
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

// newDeviceLink wraps dev and starts the event translator.
func newDeviceLink(dev wgDevice, logf func(string, ...any)) *deviceLink {
	l := &deviceLink{dev: dev, events: make(chan Event, 10)}
	flow.Safe("tunfe/link.events", logf, l.pumpEvents)
	return l
}

// pumpEvents translates the device's events onto our own channel.
//
// The device feeds its channel from a route-socket reader goroutine over a
// buffer of ten, and that reader wedges permanently once nobody is listening —
// after which no interface event is ever seen again. This loop is what makes
// "Events() must be drained" true no matter what the supervisor does with our
// channel: a full channel here drops the event rather than stalling the
// device's reader.
func (l *deviceLink) pumpEvents() {
	defer close(l.events)
	for ev := range l.dev.Events() {
		var out Event
		switch ev {
		case wgtun.EventUp:
			out = EventUp
		case wgtun.EventDown:
			out = EventDown
		case wgtun.EventMTUUpdate:
			out = EventMTUUpdate
		default:
			continue
		}
		select {
		case l.events <- out:
		default:
		}
	}
}

func (l *deviceLink) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if err := checkOffset(offset); err != nil {
		return 0, err
	}
	return l.dev.Read(bufs, sizes, offset)
}

func (l *deviceLink) Write(bufs [][]byte, offset int) (int, error) {
	if err := checkOffset(offset); err != nil {
		return 0, err
	}
	return l.dev.Write(bufs, offset)
}

func (l *deviceLink) MTU() (int, error)     { return l.dev.MTU() }
func (l *deviceLink) Name() (string, error) { return l.dev.Name() }
func (l *deviceLink) Events() <-chan Event  { return l.events }
func (l *deviceLink) BatchSize() int        { return l.dev.BatchSize() }
func (l *deviceLink) Close() error          { return l.dev.Close() }
