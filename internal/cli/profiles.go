package cli

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/spf13/cobra"
)

func newProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List and inspect region profiles",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List built-in profiles",
		RunE: func(*cobra.Command, []string) error {
			for _, name := range config.BuiltinNames() {
				p, err := config.LoadBuiltin(name)
				if err != nil {
					return err
				}
				fmt.Printf("%-20s %s\n", name, p.Description)
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show NAME",
		Short: "Show the resolved configuration for a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			p, err := config.Resolve(args[0], config.DefaultConfigPath(), config.Overrides{})
			if err != nil {
				return err
			}
			return toml.NewEncoder(os.Stdout).Encode(p)
		},
	})
	return cmd
}
