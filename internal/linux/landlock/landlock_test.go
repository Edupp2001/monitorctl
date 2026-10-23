//go:build linux

package landlock_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Edupp2001/monitorctl/internal/linux/landlock"
	"github.com/Edupp2001/monitorctl/internal/linux/prctl"
	"github.com/Edupp2001/monitorctl/internal/policy"
)

// envChildFlag marks a re-exec of the test binary as the child process that
// applies the ruleset and then exercises it.
const envChildFlag = "MONITORCTL_LANDLOCK_TEST_CHILD"

// TestMain intercepts re-exec so the child runs the sandboxed check without
// going through the regular test framework output.
func TestMain(m *testing.M) {
	if os.Getenv(envChildFlag) == "1" {
		os.Exit(childMain())
	}
	os.Exit(m.Run())
}

// childMain runs in the re-exec'd test binary. It applies Landlock using the
// fd inherited from the parent, then:
//
//   - writes to $MONITORCTL_TEST_ALLOW (must succeed)
//   - writes to $MONITORCTL_TEST_DENY  (must fail with EACCES)
//   - reads  $MONITORCTL_TEST_READ     (only if set; must succeed)
//
// Exit codes:
//
//	0  everything as expected
//	1  allow write unexpectedly blocked
//	2  deny write unexpectedly succeeded / wrong errno
//	3  pre-exec setup failed
//	4  read unexpectedly blocked
func childMain() int {
	fdStr := os.Getenv("MONITORCTL_TEST_LL_FD")
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "child: bad fd %q: %v\n", fdStr, err)
		return 3
	}
	if err := prctl.SetNoNewPrivs(); err != nil {
		fmt.Fprintf(os.Stderr, "child: PR_SET_NO_NEW_PRIVS: %v\n", err)
		return 3
	}
	if err := landlock.RestrictSelf(fd); err != nil {
		fmt.Fprintf(os.Stderr, "child: RestrictSelf: %v\n", err)
		return 3
	}
	_ = unix.Close(fd)

	allowPath := os.Getenv("MONITORCTL_TEST_ALLOW")
	denyPath := os.Getenv("MONITORCTL_TEST_DENY")
	readPath := os.Getenv("MONITORCTL_TEST_READ")

	if err := os.WriteFile(allowPath, []byte("x"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "child: allow write failed: %v\n", err)
		return 1
	}
	if err := os.WriteFile(denyPath, []byte("x"), 0o644); err == nil {
		fmt.Fprintf(os.Stderr, "child: deny write unexpectedly succeeded\n")
		return 2
	} else if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "child: deny write failed with unexpected error: %v\n", err)
		return 2
	}
	if readPath != "" {
		if _, err := os.ReadFile(readPath); err != nil {
			fmt.Fprintf(os.Stderr, "child: read outside whitelist failed: %v\n", err)
			return 4
		}
	}
	return 0
}

// TestABI verifies that Landlock is available on this kernel.
func TestABI(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	abi, err := landlock.ABI()
	if err != nil {
		t.Skipf("landlock unavailable: %v", err)
	}
	if abi < 1 {
		t.Fatalf("ABI = %d, want >= 1", abi)
	}
	t.Logf("landlock ABI = %d", abi)
}

// TestRestrictBlocksWriteOutside builds a ruleset in the parent, passes it to
// a re-exec'd child, and asserts the child can write to allowDir but not to
// denyDir.
func TestRestrictBlocksWriteOutside(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}

	allowDir := t.TempDir()
	denyDir := t.TempDir()

	wl := policy.Whitelist{AllowAll: []string{allowDir}}
	rs, warns, err := landlock.NewRuleset(policy.ScopeAll, wl)
	if err != nil {
		t.Skipf("NewRuleset: %v", err)
	}
	defer rs.Close()
	if len(warns) > 0 {
		t.Logf("warnings: %v", warns)
	}

	allowPath := filepath.Join(allowDir, "file")
	denyPath := filepath.Join(denyDir, "file")

	llFile := os.NewFile(uintptr(rs.FD()), "landlock-ruleset")
	if llFile == nil {
		t.Fatalf("os.NewFile: nil")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(),
		envChildFlag+"=1",
		"MONITORCTL_TEST_LL_FD=3",
		"MONITORCTL_TEST_ALLOW="+allowPath,
		"MONITORCTL_TEST_DENY="+denyPath,
	)
	cmd.ExtraFiles = []*os.File{llFile}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("child exit=%d stderr=%q", exitErr.ExitCode(), stderr.String())
		}
		t.Fatalf("child run: %v (stderr=%q)", err, stderr.String())
	}

	if _, err := os.Stat(allowPath); err != nil {
		t.Fatalf("allow file missing after child: %v", err)
	}
	if _, err := os.Stat(denyPath); !os.IsNotExist(err) {
		t.Fatalf("deny file present after child (should have been blocked): %v", err)
	}
}

// TestRestrictScopeWriteAllowsRead verifies that under scope=write, reads are
// unrestricted even outside the whitelist, while writes are blocked.
func TestRestrictScopeWriteAllowsRead(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}

	allowDir := t.TempDir()
	denyDir := t.TempDir()

	readable := filepath.Join(denyDir, "readable")
	if err := os.WriteFile(readable, []byte("hello"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	wl := policy.Whitelist{AllowWrite: []string{allowDir}}
	rs, _, err := landlock.NewRuleset(policy.ScopeWrite, wl)
	if err != nil {
		t.Skipf("NewRuleset: %v", err)
	}
	defer rs.Close()

	allowPath := filepath.Join(allowDir, "file")
	denyPath := filepath.Join(denyDir, "should-not-exist")

	llFile := os.NewFile(uintptr(rs.FD()), "landlock-ruleset")
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(),
		envChildFlag+"=1",
		"MONITORCTL_TEST_LL_FD=3",
		"MONITORCTL_TEST_ALLOW="+allowPath,
		"MONITORCTL_TEST_DENY="+denyPath,
		"MONITORCTL_TEST_READ="+readable,
	)
	cmd.ExtraFiles = []*os.File{llFile}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("child exit=%d stderr=%q", exitErr.ExitCode(), stderr.String())
		}
		t.Fatalf("child run: %v", err)
	}
}
