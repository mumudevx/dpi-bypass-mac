package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/dns"
	"github.com/mumudevx/dpi-bypass-mac/internal/sysnet"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check environment and recover from a crashed run",
		RunE: func(*cobra.Command, []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ok := true

			// 1. Encrypted DNS reachability.
			if r, err := dns.NewDoH("https://cloudflare-dns.com/dns-query", "cloudflare"); err == nil {
				if ips, err := r.Resolve(ctx, "example.com"); err == nil && len(ips) > 0 {
					fmt.Printf("✓ DoH reachable (example.com → %s)\n", ips[0])
				} else {
					ok = false
					fmt.Printf("✗ DoH lookup failed: %v\n", err)
				}
			}

			// 2. Recover a stale system-proxy backup from a crashed run.
			statePath := sysnet.DefaultStatePath()
			if _, err := os.Stat(statePath); err == nil {
				fmt.Printf("! found leftover proxy backup (%s) — restoring\n", statePath)
				pm := sysnet.NewProxyManager(sysnet.ProxyConfig{StatePath: statePath})
				pm.Restore(ctx)
				fmt.Println("✓ restored prior system-proxy settings")
			} else {
				fmt.Println("✓ no leftover proxy state")
			}

			if !ok {
				return fmt.Errorf("one or more checks failed")
			}
			return nil
		},
	}
}
