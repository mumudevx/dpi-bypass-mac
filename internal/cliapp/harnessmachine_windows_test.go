//go:build windows

package cliapp

import "github.com/mumudevx/dpb/internal/paths"

// harnessMachineChecks describes a supported Windows machine, so that `dpb
// doctor`'s answer to "is anything wrong here" is about the state the test set
// up rather than about the runner it happens to execute on.
//
// The two checks it stands in for read the machine and nothing else.
// checkWintun() calls LoadLibraryEx on wintun.dll; checkProxyHive() asks
// scwindows.HiveStatus() whose hive an elevated dpb would write. Neither has a
// seam, and neither is about dpb's residue — which is what every test that
// failed on them is actually asking about. On the 2026-09-14 windows-latest
// run a GitHub-hosted runner has no wintun.dll, so checkWintun reported a
// FAILED check on an otherwise clean machine and six doctor tests failed
// together: rep.Failed was 1 where they wanted 0, the exit code was
// ExitDoctor (3) where they wanted ExitOK, and `--quiet`, which must print
// nothing on a clean machine, printed the remedy.
//
// The states below are the supported install, not a blanket pass. wintun is
// what `--tun` needs and dpb tells the user to download; HKCU is where
// per-user settings go when dpb is not elevated as a different account. A test
// that wants either of those BROKEN says so by setting globals.machineChecks
// itself — and the two probes keep their own tests in
// doctor_machine_windows_test.go, which drives them against the real machine
// and asserts what each reports about it.
func harnessMachineChecks() func(paths.Layout) []check {
	return func(paths.Layout) []check {
		return []check{
			{
				Name:   "wintun driver",
				State:  stateOK,
				Detail: "wintun.dll loads; --tun can create its adapter",
			},
			{
				Name:   "proxy hive",
				State:  stateOK,
				Detail: "per-user settings go to HKCU, the signed-in user's own hive",
			},
		}
	}
}
