//go:build !darwin

package cli

import (
	"context"
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"github.com/mumudevx/dpi-bypass-mac/internal/logx"
)

// runTun is unavailable off macOS (the TUN datapath is darwin-only).
func runTun(_ context.Context, _ *runFlags, _ config.Profile, _ *desync.Engine, _ *logx.Logger) error {
	return fmt.Errorf("tun mode is only supported on macOS")
}
