package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(*cobra.Command, []string) error {
			fmt.Printf("dpb %s (commit %s, built %s)\n", version, commit, date)
			return nil
		},
	}
}
