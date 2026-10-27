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
// blocks until the parent signals the child's cgroup is ready, then applies
// the pre-exec pipeline (setrlimit, PR_SET_NO_NEW_PRIVS, Landlock) and
// execs the target. On success it never returns; on error it prints to
// stderr and exits with 125 (systemd/docker pre-exec convention).
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
	landlockFD, err := parseFD(os.Getenv("MONITORCTL_LANDLOCK_FD"))
	if err != nil {
		return err
	}
	syncFD, err := parseFD(os.Getenv("MONITORCTL_SYNC_FD"))
	if err != nil {
		return err
	}

	// 0. Block until parent confirms cgroup placement.
	if syncFD >= 0 {
		var buf [1]byte
		for {
			n, rerr := unix.Read(syncFD, buf[:])
			if rerr == unix.EINTR {
				continue
			}
			if rerr != nil {
				return fmt.Errorf("sync read: %w", rerr)
			}
			if n > 0 {
				break
			}
			return fmt.Errorf("sync pipe closed without signal")
		}
		_ = unix.Close(syncFD)
	}

	// 1. setrlimit
	if err := setLimits(); err != nil {
		return err
	}

	// 2. PR_SET_NO_NEW_PRIVS
	if err := prctl.SetNoNewPrivs(); err != nil {
		return err
	}

	// 3. Landlock
	if landlockFD >= 0 {
		if err := landlock.RestrictSelf(landlockFD); err != nil {
			return err
		}
		_ = unix.Close(landlockFD)
	}

	// Phase 3.5 will extend: capset, setresuid, seccomp, MDWE, DUMPABLE.
	_ = guard

	// 4. exec
	return unix.Exec(target[0], target, filteredEnviron())
}

func setLimits() error {
	limits := []struct {
		res      int
		cur, max uint64
	}{
		{unix.RLIMIT_NPROC, 256, 256},
		{unix.RLIMIT_NOFILE, 1024, 1024},
		{unix.RLIMIT_AS, 4 << 30, 4 << 30},
	}
	for _, l := range limits {
		rlim := unix.Rlimit{Cur: l.cur, Max: l.max}
		if err := unix.Setrlimit(l.res, &rlim); err != nil {
			return fmt.Errorf("setrlimit(%d): %w", l.res, err)
		}
	}
	return nil
}

func parseFD(s string) (int, error) {
	if s == "" {
		return -1, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1, fmt.Errorf("fd parse %q: %w", s, err)
	}
	return n, nil
}
