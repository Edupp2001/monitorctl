// Package prctl wraps prctl(2) syscalls needed by monitorctl.
//
// Phase 1 only needs PR_SET_NO_NEW_PRIVS; Phase 3.5 will add PR_SET_MDWE and
// PR_SET_DUMPABLE.
package prctl

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SetNoNewPrivs sets PR_SET_NO_NEW_PRIVS=1 on the calling thread. Required
// by landlock_restrict_self(2) and irreversible.
//
// Example:
//
//	if err := prctl.SetNoNewPrivs(); err != nil { return err }
//	// subsequent setuid binaries cannot regain privileges
func SetNoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	return nil
}
