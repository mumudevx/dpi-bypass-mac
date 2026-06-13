// Package cli wires the cobra command tree for the dpb binary.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Build-time variables, set via -ldflags by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "dpb",
		Short:         "dpb — macOS DPI bypass (Turkey + global)",
		Long:          "dpb is a macOS-first DPI-bypass tool. It runs a local proxy that fragments\nthe TLS ClientHello and resolves names over encrypted DNS to defeat SNI- and\nDNS-based censorship, with region profiles for Turkey and global use.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRunCmd())
	root.AddCommand(newServiceCmd())
	root.AddCommand(newProfilesCmd())
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newVersionCmd())
	return root
}

// Execute runs the root command.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
