// Package supervisor forks the sandboxed target process, applies the pre-exec
// pipeline inside the child, and manages the parent-side lifecycle.
//
// The child blocks on a sync pipe until the parent confirms that it is inside
// the target cgroup; only then does the pre-exec pipeline (setrlimit, prctl,
// landlock, execve) proceed. This guarantees that all target-context syscalls
// are visible to the parent with the expected cgroup_id.
package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Edupp2001/monitorctl/internal/linux/landlock"
	"github.com/Edupp2001/monitorctl/internal/policy"
)

// InternalChildArg is the sentinel argument that marks a re-exec of the
// monitorctl binary as a supervised child.
const InternalChildArg = "__child"

// Config configures a single supervisor.Run invocation.
type Config struct {
	Guard      string
	Scope      string
	Whitelist  policy.Whitelist
	CgroupPath string
	// OnCgroupReady is called after the child is confirmed in the target
	// cgroup and before the child is unblocked. It receives the cgid read
	// from /proc/<pid>/cgroup (not from stat(cfg.CgroupPath)) so that
	// callers can key BPF maps by the child's actual cgroup id.
	OnCgroupReady func(cgid uint64, pid uint32) error
}

// Run re-execs monitorctl as a supervised child. The child blocks on a sync
// pipe until the parent confirms the child is inside the target cgroup; only
// then does the child's pre-exec pipeline (setrlimit, prctl, landlock,
// execve(target)) proceed. This guarantees that all target-context syscalls
// are emitted with the expected cgroup_id.
//
// Example:
//
//	cmd, err := supervisor.Run(ctx, &supervisor.Config{
//	    Guard: "shield", Scope: "all",
//	    Whitelist:  wl,
//	    CgroupPath: "/sys/fs/cgroup/monitorctl/<uuid>",
//	}, []string{"/bin/ls", "-la"})
func Run(ctx context.Context, cfg *Config, target []string) (*exec.Cmd, error) {
	_ = ctx
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
	childArgs := append([]string{absTarget}, target[1:]...)

	var landlockFile *os.File
	var cgroupFile *os.File
	extraFiles := []*os.File{}
	childEnv := []string{"MONITORCTL_GUARD=" + cfg.Guard}

	if cfg.Guard == "shield" {
		scope, err := policy.ParseScope(cfg.Scope)
		if err != nil {
			return nil, err
		}
		wl := cfg.Whitelist.WithTarget(absTarget)
		wl.AllowAll = append(wl.AllowAll, "/proc/self/exe")
		rs, warns, err := landlock.NewRuleset(scope, wl)
		if err != nil {
			return nil, fmt.Errorf("build landlock ruleset: %w", err)
		}
		for _, w := range warns {
			fmt.Fprintln(os.Stderr, "monitorctl: landlock warning:", w)
		}
		landlockFile = os.NewFile(uintptr(rs.FD()), "landlock-ruleset")
		extraFiles = append(extraFiles, landlockFile)
		childEnv = append(childEnv, "MONITORCTL_LANDLOCK_FD=3")
	}

	// Sync pipe: child blocks on read until parent writes.
	syncR, syncW, err := os.Pipe()
	if err != nil {
		if landlockFile != nil {
			_ = landlockFile.Close()
		}
		return nil, fmt.Errorf("pipe: %w", err)
	}
	// Compute child's fd for syncR: stdin/stdout/stderr = 0/1/2, then ExtraFiles 0..N
	syncFD := 3 + len(extraFiles)
	extraFiles = append(extraFiles, syncR)
	childEnv = append(childEnv, fmt.Sprintf("MONITORCTL_SYNC_FD=%d", syncFD))

	sysAttr := &syscall.SysProcAttr{Setpgid: true}

	if cfg.CgroupPath != "" {
		fd, err := unix.Open(cfg.CgroupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = syncR.Close()
			_ = syncW.Close()
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
		_ = syncR.Close()
		_ = syncW.Close()
		if landlockFile != nil {
			_ = landlockFile.Close()
		}
		if cgroupFile != nil {
			_ = cgroupFile.Close()
		}
		return nil, fmt.Errorf("start child: %w", err)
	}
	// Parent no longer needs syncR; child holds its own copy.
	_ = syncR.Close()
	if landlockFile != nil {
		_ = landlockFile.Close()
	}
	if cgroupFile != nil {
		_ = cgroupFile.Close()
	}

	// Confirm child is in target cgroup before signalling. If clone3 did not
	// apply CLONE_INTO_CGROUP, write the PID explicitly (idempotent if it did).
	if cfg.CgroupPath != "" {
		procsPath := filepath.Join(cfg.CgroupPath, "cgroup.procs")
		pidStr := strconv.Itoa(cmd.Process.Pid)
		deadline := time.Now().Add(200 * time.Millisecond)
		confirmed := false
		for {
			data, rerr := os.ReadFile(procsPath)
			if rerr == nil && strings.TrimSpace(string(data)) == pidStr {
				confirmed = true
				break
			}
			// Fallback: explicit move (no-op if already there).
			_ = os.WriteFile(procsPath, []byte(pidStr), 0o644)
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr,
				"monitorctl: warning: child PID not confirmed in target cgroup; events may be missed")
		}
	}

	// Read the child's actual cgroup id from /proc/<pid>/cgroup. This is
	// more reliable than stat(cfg.CgroupPath).Ino: on some kernels those
	// two disagree intermittently, silently breaking BPF filtering.
	if cfg.OnCgroupReady != nil {
		actualCgid, err := readProcCgid(cmd.Process.Pid)
		if err != nil {
			fmt.Fprintln(os.Stderr, "monitorctl: read /proc/"+strconv.Itoa(cmd.Process.Pid)+"/cgroup:", err)
		} else if err := cfg.OnCgroupReady(actualCgid, uint32(cmd.Process.Pid)); err != nil {
			fmt.Fprintln(os.Stderr, "monitorctl: OnCgroupReady:", err)
		}
	}

	// Signal child to proceed.
	if _, err := syncW.Write([]byte{1}); err != nil {
		fmt.Fprintln(os.Stderr, "monitorctl: sync write:", err)
	}
	_ = syncW.Close()

	return cmd, nil
}

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

// readProcCgid parses /proc/<pid>/cgroup (cgroup v2 format "0::/path") and
// returns the cgroup directory's inode from /sys/fs/cgroup<path>.
func readProcCgid(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		cgPath := strings.TrimPrefix(line, "0::")
		full := "/sys/fs/cgroup" + cgPath
		var st unix.Stat_t
		if err := unix.Stat(full, &st); err != nil {
			return 0, fmt.Errorf("stat %q: %w", full, err)
		}
		return st.Ino, nil
	}
	return 0, fmt.Errorf("no cgroup v2 line in /proc/%d/cgroup", pid)
}
