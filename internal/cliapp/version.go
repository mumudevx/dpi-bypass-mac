package cliapp

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
)

func newVersionCmd(g *globals) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the build identity",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if !asJSON {
				fmt.Fprintln(g.env.Stdout, buildinfo.Short())
				return nil
			}
			// Dirty is reported rather than hidden: a binary built from an
			// uncommitted tree cannot match any published checksum, and a bug
			// report that omits that wastes everyone's time.
			v := struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Commit    string `json:"commit"`
				Date      string `json:"date"`
				Dirty     bool   `json:"dirty"`
				Platform  string `json:"platform"`
				UserAgent string `json:"user_agent"`
			}{
				Name:      buildinfo.Name,
				Version:   buildinfo.V(),
				Commit:    buildinfo.C(),
				Date:      buildinfo.D(),
				Dirty:     buildinfo.Dirty(),
				Platform:  buildinfo.Platform(),
				UserAgent: buildinfo.UserAgent(),
			}
			enc := json.NewEncoder(g.env.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(v); err != nil {
				return fmt.Errorf("version: write JSON: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the build identity as JSON")
	return cmd
}
