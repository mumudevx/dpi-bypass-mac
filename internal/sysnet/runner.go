// Package sysnet performs macOS network integration: configuring and restoring
// the system proxy via networksetup. All external commands go through a
// CommandRunner so the logic is unit-testable with a fake.
package sysnet

import (
	"context"
	"os/exec"
)

// CommandRunner runs an external command and returns its combined output.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner runs commands via os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
