package netstate

import "github.com/mumudevx/dpb/internal/sysport"

// These are aliases, not definitions: netstate.Result and sysport.Result are
// the same type. That is deliberate and load-bearing. Roughly two hundred
// references to these names live outside this package — 51 to Result alone —
// and an alias moves the declaration without touching any of them.
type (
	Runner     = sysport.Runner
	Result     = sysport.Result
	RouteEntry = sysport.RouteEntry
	RIBReader  = sysport.RIBReader
	ProxyState = sysport.ProxyState
	Facts      = sysport.Facts
	VPNState   = sysport.VPNState
)
