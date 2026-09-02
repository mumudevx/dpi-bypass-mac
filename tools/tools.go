//go:build tools

// Package tools pins the module's dependency set.
//
// Nothing in the shipped binary imports this file: the `tools` build tag is
// never set for a normal build, vet or test run. It exists because `go mod
// tidy` walks the import graph under *all* build tags, so these blank imports
// are what stop tidy from pruning a dependency that a milestone which has not
// been written yet will need. M0 pins the whole tree's dependency set once so
// that no later milestone has to touch go.mod or go.sum.
package tools

import (
	_ "github.com/BurntSushi/toml"
	_ "github.com/google/go-cmp/cmp"
	_ "github.com/miekg/dns"
	_ "github.com/spf13/cobra"
	_ "golang.org/x/net/route"
	_ "golang.org/x/sys/unix"
	_ "golang.zx2c4.com/wireguard/tun"
	_ "gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	_ "gvisor.dev/gvisor/pkg/tcpip/link/channel"
	_ "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	_ "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	_ "gvisor.dev/gvisor/pkg/tcpip/stack"
	_ "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	_ "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	_ "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)
