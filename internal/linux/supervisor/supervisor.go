// Package supervisor forks the sandboxed target process, applies the pre-exec
// pipeline inside the child, and provides the parent-side lifecycle.
//
// Child pre-exec pipeline (current):
//
//  1. setrlimit(NPROC=256, NOFILE=1024, AS=4GiB)
//  2. prctl(PR_SET_NO_NEW_PRIVS)
//  3. landlock_restrict_self (only when --guard=shield)
//  4. execve(target)
//
// Phase 3.5 will extend the pipeline with capset/setresuid/seccomp/MDWE.
//
// The target binary itself is resolved to an absolute path via exec.LookPath
// and auto-added to allow_all in-memory, so the initial execve(target) — which
// is checked by Landlock because the ruleset is applied before execve —
// succeeds even if the target's path is not listed in the TOML.
package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/Edupp2001/monitorctl/internal/linux/landlock"
	"github.com/Edupp2001/monitorctl/internal/policy"
)

// InternalChildArg is the sentinel argument that marks a re-exec of the
// monitorctl binary as a supervised child.
const InternalChildArg = "__child"

// Config carries everything the supervisor needs.
type Config struct {
	// Guard is "warn" or "shield". When "warn", Landlock is not applied.
	Guard string
	// Scope is "all", "exec" or "write".
	Scope string
	// Whitelist defines the positive permissions inside the cell.
	// The target binary is auto-added to AllowAll at run time.
	Whitelist policy.Whitelist
	// CgroupPath, if non-empty, is the leaf cgroup directory the child is
	// atomically placed into at clone time (clone3 CLONE_INTO_CGROUP).
	CgroupPath string
}

// Run re-execs monitorctl as a supervised child, which applies the pre-exec
// pipeline and then execve()s target[0] with target as its argv.
//
// target[0] is resolved via exec.LookPath and made absolute; the resolved
// path is used both for execve and for the in-memory allow_all entry.
//
// Returns the started *exec.Cmd. The caller is expected to Wait() on it.
//
// Example:
//
//	cmd, err := supervisor.Run(ctx, &supervisor.Config{
//	    Guard: "shield", Scope: "all",
//	    Whitelist: policy.Whitelist{
//	        AllowRead:  []string{"/etc/passwd"},
//	        AllowWrite: []string{"/tmp"},
//	    },
//	    CgroupPath: "/sys/fs/cgroup/monitorctl/<uuid>",
//	}, []string{"/bin/ls", "-la"})
//	if err != nil { return err }
//	err = cmd.Wait()
func Run(ctx context.Context, cfg *Config, target []string) (*exec.Cmd, error) {
	_ = ctx // reserved for future cancellation of setup steps
	if len(target) == 0 {
		return nil, fmt.Errorf("supervisor: empty target")
	}

	absTarget, err := exec.LookPath(target[0])
	if err != nil {
		return nil, fmt.Errorf("lookpath %q: %w", target[0], err)
	}
	absTarget, err = filepath.Abs(absTarget)
	if err != nil {
		return nil, fmt.Errorf("abs %q: %w", absTarget, err)
	}
	// Replace argv[0] with the absolute path so execve and the Landlock rule
	// agree on identity, and PATH is not consulted again in the child.
	childArgs := append([]string{absTarget}, target[1:]...)

	var landlockFile *os.File
	var cgroupFile *os.File
	var extraFiles []*os.File
	childEnv := []string{
		"MONITORCTL_GUARD=" + cfg.Guard,
		"MONITORCTL_LANDLOCK_FD=",
	}

	if cfg.Guard == "shield" {
		scope, err := policy.ParseScope(cfg.Scope)
		if err != nil {
			return nil, err
		}
		wl := cfg.Whitelist.WithTarget(absTarget)
		rs, warns, err := landlock.NewRuleset(scope, wl)
		if err != nil {
			return nil, fmt.Errorf("build landlock ruleset: %w", err)
		}
		for _, w := range warns {
			fmt.Fprintln(os.Stderr, "monitorctl: landlock warning:", w)
		}
		// ExtraFiles[0] is fd 3 in the child (after stdin/stdout/stderr).
		landlockFile = os.NewFile(uintptr(rs.FD()), "landlock-ruleset")
		extraFiles = append(extraFiles, landlockFile)
		childEnv = []string{
			"MONITORCTL_GUARD=" + cfg.Guard,
			"MONITORCTL_LANDLOCK_FD=3",
		}
	}

	sysAttr := &syscall.SysProcAttr{Setpgid: true}

	if cfg.CgroupPath != "" {
		fd, err := unix.Open(cfg.CgroupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			if landlockFile != nil {
				_ = landlockFile.Close()
			}
			return nil, fmt.Errorf("open cgroup %s: %w", cfg.CgroupPath, err)
		}
		cgroupFile = os.NewFile(uintptr(fd), cfg.CgroupPath)
		sysAttr.UseCgroupFD = true
		sysAttr.CgroupFD = int(fd)
	}

	cmd := exec.Command("/proc/self/exe",
		append([]string{InternalChildArg, "--"}, childArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = extraFiles
	cmd.Env = append(filteredEnviron(), childEnv...)
	cmd.SysProcAttr = sysAttr

	if err := cmd.Start(); err != nil {
		if landlockFile != nil {
			_ = landlockFile.Close()
		}
		if cgroupFile != nil {
			_ = cgroupFile.Close()
		}
		return nil, fmt.Errorf("start child: %w", err)
	}
	if landlockFile != nil {
		_ = landlockFile.Close()
	}
	if cgroupFile != nil {
		_ = cgroupFile.Close()
	}
	return cmd, nil
}

// filteredEnviron returns os.Environ() minus any MONITORCTL_* variables, so
// that a monitorctl re-exec does not leak internal state into the target.
func filteredEnviron() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, e := range src {
		if strings.HasPrefix(e, "MONITORCTL_") {
			continue
		}
		out = append(out, e)
	}
	return out
}
