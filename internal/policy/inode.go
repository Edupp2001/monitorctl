package policy

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Inode identifies a filesystem object by (device, inode) pair. Landlock
// rules are keyed by these, which is immune to mount-namespace tricks
// inside the target.
type Inode struct {
	Path string // original path, for logging only
	Dev  uint64
	Ino  uint64
}

// ResolvePath stat()s path and returns its Inode identity. Returns an error
// if the path does not exist or cannot be stat()'d.
//
// Example:
//
//	ino, err := policy.ResolvePath("/tmp")
//	// ino.Dev, ino.Ino identify /tmp's directory inode
func ResolvePath(path string) (Inode, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return Inode{}, fmt.Errorf("stat %q: %w", path, err)
	}
	return Inode{Path: path, Dev: uint64(st.Dev), Ino: st.Ino}, nil
}

// ResolvePaths resolves every path, returning resolved inodes and one warning
// per path that could not be stat()'d. Never returns an error — a missing
// path is a warning per ARCHITECTURE.md.
func ResolvePaths(paths []string) ([]Inode, []string) {
	var inodes []Inode
	var warnings []string
	for _, p := range paths {
		ino, err := ResolvePath(p)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		inodes = append(inodes, ino)
	}
	return inodes, warnings
}
