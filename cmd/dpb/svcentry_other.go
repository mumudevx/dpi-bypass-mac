//go:build !windows

package main

import "os"

// armServiceStop and runAsWindowsService are the non-Windows halves of the
// service entry point in svcentry_windows.go.
//
// There is no service control manager here, so there is nothing to hand the
// process to and nothing to relay a stop from: main() takes the ordinary CLI
// path, and installSignals' relay call does nothing. They are a pair of stubs
// rather than a build-tagged `if` in main.go so that main.go compiles
// identically on every platform and the branch it does have stays readable.

func armServiceStop(chan<- os.Signal) {}

func runAsWindowsService() (int, bool) { return 0, false }
