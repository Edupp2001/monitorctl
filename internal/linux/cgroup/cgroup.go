// Package cgroup creates and manages the cgroup v2 hierarchy used to sandbox
// the target process tree.
//
// Layout:
//
//	/sys/fs/cgroup/monitorctl/               (parent, +pids +memory enabled)
//	└── <uuid>/                               (one per monitorctl run)
//	    ├── cgroup.procs                     (target pid)
//	    ├── cgroup.kill                      (write 1 → SIGKILL tree)
//	    ├── pids.max      = 256
//	    └── memory.max    = 1 GiB
//
// A cgroup is created before the target is forked and the target is placed
// into it atomically via clone3(CLONE_INTO_CGROUP) (SysProcAttr.CgroupFD).
// Killing the group via cgroup.kill SIGKILLs every descendant atomically.
package cgroup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// RootDir is the cgroup v2 mount root.
	RootDir = "/sys/fs/cgroup"
	// BaseDir is the shared parent for every monitorctl run.
	BaseDir = RootDir + "/monitorctl"
	// PidsMax is written to <uuid>/pids.max.
	PidsMax = 256
	// MemoryMaxBytes is written to <uuid>/memory.max (1 GiB).
	MemoryMaxBytes = 1 << 30
)

// Group is a handle to a per-run cgroup. Path is the leaf directory;
// callers pass it to supervisor.Config.CgroupPath.
type Group struct {
	Path string
}

// Create sets up the parent cgroup (idempotently) and creates a fresh leaf
// with pids.max and memory.max. Returns an error if cgroup v2 is not
// available or the required controllers cannot be enabled.
//
// Example:
//
//	g, err := cgroup.Create()
//	if err != nil { return err }
//	defer g.Close(true) // after Kill
func Create() (*Group, error) {
	if _, err := os.Stat(filepath.Join(RootDir, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("cgroup v2 not available at %s: %w", RootDir, err)
	}

	if err := os.MkdirAll(BaseDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", BaseDir, err)
	}

	if err := enableControllers(BaseDir, "pids", "memory"); err != nil {
		return nil, fmt.Errorf("enable controllers at %s: %w", BaseDir, err)
	}

	uuid, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("uuid: %w", err)
	}

	leaf := filepath.Join(BaseDir, uuid)
	if err := os.Mkdir(leaf, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", leaf, err)
	}

	g := &Group{Path: leaf}

	if err := os.WriteFile(filepath.Join(leaf, "pids.max"),
		[]byte(fmt.Sprintf("%d", PidsMax)), 0o644); err != nil {
		_ = g.Close(false)
		return nil, fmt.Errorf("write pids.max: %w", err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "memory.max"),
		[]byte(fmt.Sprintf("%d", MemoryMaxBytes)), 0o644); err != nil {
		_ = g.Close(false)
		return nil, fmt.Errorf("write memory.max: %w", err)
	}

	return g, nil
}

// Kill atomically SIGKILLs every process in the cgroup by writing "1" to
// cgroup.kill. It does not wait for them to die; use Close(true) afterwards
// to reap and remove the directory.
//
// Example:
//
//	if err := g.Kill(); err != nil { log.Warn("kill", "error", err) }
func (g *Group) Kill() error {
	p := filepath.Join(g.Path, "cgroup.kill")
	if err := os.WriteFile(p, []byte("1"), 0o644); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // already gone (never populated, or manual cleanup)
		}
		return fmt.Errorf("write cgroup.kill: %w", err)
	}
	return nil
}

// Close removes the cgroup directory.
//
// When force is true, Close polls the cgroup for up to 2 seconds waiting for
// it to become empty, then calls rmdir. This is the right mode after Kill.
//
// When force is false, Close requires the cgroup to be empty right now and
// returns an error immediately otherwise. Use this for --on-exit=leave where
// the target may still be running.
//
// Example:
//
//	_ = g.Kill()
//	if err := g.Close(true); err != nil { log.Warn("cleanup", "error", err) }
func (g *Group) Close(force bool) error {
	if !force {
		if !isEmpty(g.Path) {
			return fmt.Errorf("cgroup %s not empty", g.Path)
		}
		return rmdir(g.Path)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if isEmpty(g.Path) {
			return rmdir(g.Path)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("cgroup %s still populated after 2s", g.Path)
}

// OOMScoreAdj writes v to /proc/self/oom_score_adj. With v=-1000 the calling
// process is exempt from the OOM killer (requires CAP_SYS_RESOURCE).
//
// Example:
//
//	if err := cgroup.OOMScoreAdj(-1000); err != nil { log.Warn("oom", "error", err) }
func OOMScoreAdj(v int) error {
	return os.WriteFile("/proc/self/oom_score_adj",
		[]byte(fmt.Sprintf("%d", v)), 0o644)
}

func enableControllers(dir string, ctrls ...string) error {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup.controllers: %w", err)
	}
	available := strings.Fields(string(data))
	have := make(map[string]bool, len(available))
	for _, c := range available {
		have[c] = true
	}
	var want []string
	for _, c := range ctrls {
		if !have[c] {
			return fmt.Errorf("controller %q not available (have: %v)", c, available)
		}
		want = append(want, "+"+c)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"),
		[]byte(strings.Join(want, " ")), 0o644); err != nil {
		return fmt.Errorf("write subtree_control: %w", err)
	}
	return nil
}

func isEmpty(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return true // treat as empty; rmdir will fail meaningfully if not
	}
	return len(strings.TrimSpace(string(data))) == 0
}

func rmdir(dir string) error {
	err := unix.Rmdir(dir)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return fmt.Errorf("rmdir %s: %w", dir, err)
	}
	return nil
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
