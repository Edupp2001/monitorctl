package supervisor

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/Edupp2001/monitorctl/internal/linux/landlock"
	"github.com/Edupp2001/monitorctl/internal/linux/prctl"
)

// RunChild is invoked from main when os.Args[1] == InternalChildArg. It
// applies the pre-exec pipeline and then execs the target. On success it
// never returns; on error it prints the reason and exits with 125 (the
// pre-exec-failure convention used by systemd/docker).
//
// Example (inside main):
//
//	if len(os.Args) >= 2 && os.Args[1] == supervisor.InternalChildArg {
//	    supervisor.RunChild(os.Args[2:])
//	}
func RunChild(args []string) {
	if err := doChild(args); err != nil {
		fmt.Fprintln(os.Stderr, "monitorctl child:", err)
		os.Exit(125)
	}
}

func doChild(args []string) error {
	if len(args) < 2 || args[0] != "--" {
		return fmt.Errorf("expected -- separator, got %q", args)
	}
	target := args[1:]

	guard := os.Getenv("MONITORCTL_GUARD")
	landlockFD, err := parseLandlockFD(os.Getenv("MONITORCTL_LANDLOCK_FD"))
	if err != nil {
		return err
	}

	// 1. setrlimit — anti-fork-bomb, anti-fd-exhaustion, anti-VM-exhaustion.
	if err := setLimits(); err != nil {
		return err
	}

	// 2. PR_SET_NO_NEW_PRIVS — mandatory before landlock_restrict_self.
	if err := prctl.SetNoNewPrivs(); err != nil {
		return err
	}

	// 3. Landlock (only when guard=shield).
	if landlockFD >= 0 {
		if err := landlock.RestrictSelf(landlockFD); err != nil {
			return err
		}
		_ = unix.Close(landlockFD)
	}

	// Phase 3.5 will extend: capset(0), setresuid(nobody), seccomp, MDWE.
	_ = guard

	// 4. Exec target.
	return unix.Exec(target[0], target, filteredEnviron())
}

func setLimits() error {
	limits := []struct {
		res      int
		cur, max uint64
	}{
		{unix.RLIMIT_NPROC, 256, 256},
		{unix.RLIMIT_NOFILE, 1024, 1024},
		{unix.RLIMIT_AS, 4 << 30, 4 << 30}, // 4 GiB
	}
	for _, l := range limits {
		rlim := unix.Rlimit{Cur: l.cur, Max: l.max}
		if err := unix.Setrlimit(l.res, &rlim); err != nil {
			return fmt.Errorf("setrlimit(%d): %w", l.res, err)
		}
	}
	return nil
}

func parseLandlockFD(s string) (int, error) {
	if s == "" {
		return -1, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1, fmt.Errorf("MONITORCTL_LANDLOCK_FD: %w", err)
	}
	return n, nil
}
