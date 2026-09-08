//go:build !windows

package netstate

import (
	"fmt"
	"os"
)

// fsyncDir makes a directory entry durable. Creating a file and fsyncing its
// contents does not persist the name that points at it.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("netstate: open directory %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("netstate: fsync directory %s: %w", dir, err)
	}
	return nil
}
