//go:build !windows

package paths

import "os"

// ReplaceFile moves oldpath onto newpath, replacing whatever is there.
//
// On Unix this is one call and it cannot lose a race. rename(2) is atomic by
// specification and it succeeds over a destination that other processes — or
// other goroutines in this one — currently hold open: the old inode simply
// loses its name and dies with the last descriptor. That is the property every
// write-temp-then-rename in this tree is written against, and it is the
// property the Windows leaf has to buy back by hand (see replace_windows.go).
func ReplaceFile(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
