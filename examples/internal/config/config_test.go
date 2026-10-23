package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Edupp2001/monitorctl/internal/config"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wl.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	p := writeTemp(t, `allow_read  = ["/etc/hostname"]
allow_write = ["/tmp"]
allow_all   = ["/bin/ls"]`)
	wl, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(wl.AllowRead) != 1 || wl.AllowRead[0] != "/etc/hostname" {
		t.Fatalf("AllowRead = %v", wl.AllowRead)
	}
	if len(wl.AllowWrite) != 1 || wl.AllowWrite[0] != "/tmp" {
		t.Fatalf("AllowWrite = %v", wl.AllowWrite)
	}
	if len(wl.AllowAll) != 1 || wl.AllowAll[0] != "/bin/ls" {
		t.Fatalf("AllowAll = %v", wl.AllowAll)
	}
}

func TestLoadRejectsEmpty(t *testing.T) {
	p := writeTemp(t, `allow_read = []`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for empty whitelist")
	}
}

func TestLoadRejectsRelative(t *testing.T) {
	p := writeTemp(t, `allow_write = ["relative/path"]`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestLoadRejectsDuplicateAcrossLists(t *testing.T) {
	p := writeTemp(t, `allow_read  = ["/tmp"]
allow_write = ["/tmp"]`)
	_, err := config.Load(p)
	if err == nil {
		t.Fatal("expected error for duplicate path")
	}
	if !strings.Contains(err.Error(), "/tmp") {
		t.Fatalf("error does not mention path: %v", err)
	}
}

func TestEnsurePathsCreatesWriteDirs(t *testing.T) {
	dir := t.TempDir()
	newDir := filepath.Join(dir, "created")
	p := writeTemp(t, `allow_write = ["`+newDir+`"]`)
	wl, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if warns := wl.EnsurePaths(); len(warns) > 0 {
		t.Fatalf("EnsurePaths: %v", warns)
	}
	if st, err := os.Stat(newDir); err != nil || !st.IsDir() {
		t.Fatalf("dir not created: %v %v", st, err)
	}
}

func TestEnsurePathsSkipsReadOnly(t *testing.T) {
	dir := t.TempDir()
	newDir := filepath.Join(dir, "read-only-should-not-exist")
	p := writeTemp(t, `allow_read = ["`+newDir+`"]`)
	wl, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_ = wl.EnsurePaths()
	if _, err := os.Stat(newDir); !os.IsNotExist(err) {
		t.Fatalf("allow_read dir should not be created: %v", err)
	}
}
