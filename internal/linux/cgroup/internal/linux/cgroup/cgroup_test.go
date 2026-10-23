//go:build linux

package cgroup_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Edupp2001/monitorctl/internal/linux/cgroup"
)

func TestCreateKillClose(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for cgroup v2 setup")
	}

	g, err := cgroup.Create()
	if err != nil {
		t.Skipf("cgroup unavailable: %v", err)
	}

	cmd := exec.Command("sleep", "100")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	if err := os.WriteFile(filepath.Join(g.Path, "cgroup.procs"),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}

	if err := g.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	// sleep must die (Wait returns non-nil on SIGKILL)
	if err := cmd.Wait(); err == nil {
		t.Fatalf("sleep survived cgroup.kill")
	}

	if err := g.Close(true); err != nil {
		t.Fatalf("Close(true): %v", err)
	}
	if _, err := os.Stat(g.Path); !os.IsNotExist(err) {
		t.Fatalf("cgroup dir still present: %v", err)
	}
}

func TestCloseFailsWhenNotEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	g, err := cgroup.Create()
	if err != nil {
		t.Skipf("cgroup unavailable: %v", err)
	}
	cmd := exec.Command("sleep", "100")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() {
		_ = g.Kill()
		_ = g.Close(true)
		_ = cmd.Process.Kill()
	}()
	if err := os.WriteFile(filepath.Join(g.Path, "cgroup.procs"),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}
	if err := g.Close(false); err == nil {
		t.Fatalf("Close(false) should fail for populated cgroup")
	}
}
