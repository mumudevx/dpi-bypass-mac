//go:build darwin

// Package tun is the transparent interception front-end: a utun device fed into
// a gVisor userspace TCP/IP stack. Every intercepted TCP flow is relayed to its
// real destination with the desync engine applied — catching even apps that
// ignore the system proxy. Requires root (utun creation + routing).
package tun

import "golang.zx2c4.com/wireguard/tun"

// Device wraps a macOS utun interface created via wireguard/tun, which performs
// the PF_SYSTEM/SYSPROTO_CONTROL dance and handles the 4-byte AF prefix.
type Device struct {
	dev  tun.Device
	name string
	mtu  int
}

// Open creates a utun device. Pass "utun" to let the kernel pick the index.
// Requires root.
func Open(name string, mtu int) (*Device, error) {
	if name == "" {
		name = "utun"
	}
	d, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}
	n, _ := d.Name()
	m, err := d.MTU()
	if err != nil || m == 0 {
		m = mtu
	}
	return &Device{dev: d, name: n, mtu: m}, nil
}

// Name returns the assigned interface name (e.g. utun4).
func (d *Device) Name() string { return d.name }

// MTU returns the device MTU.
func (d *Device) MTU() int { return d.mtu }

// Close tears down the utun device (which removes the interface).
func (d *Device) Close() error { return d.dev.Close() }
