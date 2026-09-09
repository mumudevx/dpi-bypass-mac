//go:build windows

package scwindows

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestIphlpProceduresResolve can only run on a Windows host: CI does not yet
// run one for this project (see
// docs/superpowers/plans/2026-09-09-windows-parity-03-scwindows.md, "Nothing
// here can be executed" — GOOS=windows go vet is the strongest check
// available today, and it only proves this file compiles, not that any of
// these assertions have ever passed).
//
// It is the cheapest guard available against a typo'd export name or a
// procedure absent on a supported Windows version: LazyProc resolves lazily,
// so a bad name would otherwise surface as a panic the first time the real
// code path calls it, on someone's machine, mid-operation — the Windows
// analogue of checking a CLI exists on PATH before parsing its output.
func TestIphlpProceduresResolve(t *testing.T) {
	procs := []struct {
		name string
		proc *windows.LazyProc
	}{
		{"CreateIpForwardEntry2", procCreateIpForwardEntry2},
		{"DeleteIpForwardEntry2", procDeleteIpForwardEntry2},
		{"GetBestRoute2", procGetBestRoute2},
		{"CreateUnicastIpAddressEntry", procCreateUnicastIpAddressEntry},
		{"DeleteUnicastIpAddressEntry", procDeleteUnicastIpAddressEntry},
		{"InitializeUnicastIpAddressEntry", procInitializeUnicastIpAddressEntry},
		{"GetIpInterfaceEntry", procGetIpInterfaceEntry},
		{"SetIpInterfaceEntry", procSetIpInterfaceEntry},
		{"ConvertInterfaceLuidToIndex", procConvertInterfaceLuidToIndex},
		{"InternetSetOptionW", procInternetSetOptionW},
		{"WinHttpGetIEProxyConfigForCurrentUser", procWinHttpGetIEProxyConfigForCurrentUser},
		{"SendMessageTimeoutW", procSendMessageTimeoutW},
	}

	for _, p := range procs {
		if err := p.proc.Find(); err != nil {
			t.Errorf("%s: does not resolve: %v", p.name, err)
		}
	}
}
