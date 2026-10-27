package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// atFDCWD mirrors AT_FDCWD from <fcntl.h> (-100).
const atFDCWD int32 = -100

// ResolveEventPath resolves rawPath (a null-terminated path emitted by a BPF
// event) to an absolute path, using dirfd or the target's cwd as the base.
//
// The result is best-effort: symlinks and target-side mount-namespace tricks
// are not followed (documented limitation — Landlock enforcement is not
// affected, but a violation might be silently missed in the log).
//
// Example:
//
//	abs, err := policy.ResolvePath(1234, -100, []byte("foo\x00"))
//	// abs == "/cwd/of/pid/1234/foo"
func ResolveEventPath(pid uint32, dirfd int32, rawPath []byte) (string, error) {
	n := bytes.IndexByte(rawPath, 0)
	if n < 0 {
		n = len(rawPath)
	}
	path := string(rawPath[:n])
	if path == "" {
		return "", errors.New("empty path")
	}
	if path[0] == '/' {
		return filepath.Clean(path), nil
	}

	var base string
	switch {
	case dirfd == atFDCWD:
		b, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return "", fmt.Errorf("readlink /proc/%d/cwd: %w", pid, err)
		}
		base = b
	case dirfd >= 0:
		b, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
		if err != nil {
			return "", fmt.Errorf("readlink /proc/%d/fd/%d: %w", pid, dirfd, err)
		}
		base = b
	default:
		return "", fmt.Errorf("invalid dirfd %d", dirfd)
	}

	return filepath.Clean(base + "/" + path), nil
}
