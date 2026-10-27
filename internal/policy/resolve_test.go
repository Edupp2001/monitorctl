package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Edupp2001/monitorctl/internal/policy"
)

func TestResolveAbsolute(t *testing.T) {
	got, err := policy.ResolveEventPath(0, -100, []byte("/etc/passwd\x00"))
	if err != nil {
		t.Fatalf("ResolvePath: %v", err)
	}
	if got != "/etc/passwd" {
		t.Fatalf("got %q, want /etc/passwd", got)
	}
}

func TestResolveRelativeCwd(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	got, err := policy.ResolveEventPath(uint32(os.Getpid()), -100, []byte("foo\x00"))
	if err != nil {
		t.Fatalf("ResolvePath: %v", err)
	}
	want := filepath.Join(cwd, "foo")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveInvalidDirfd(t *testing.T) {
	_, err := policy.ResolveEventPath(1, -1, []byte("foo\x00"))
	if err == nil {
		t.Fatal("expected error for invalid dirfd")
	}
}

func TestMatchWhitelist(t *testing.T) {
	wl := policy.Whitelist{
		AllowRead:  []string{"/etc"},
		AllowWrite: []string{"/tmp"},
		AllowAll:   []string{"/bin"},
	}
	cases := []struct {
		path string
		mask policy.AccessMask
		ok   bool
	}{
		{"/bin/ls", policy.AccessRWX, true},
		{"/tmp/foo", policy.AccessRW, true},
		{"/etc/passwd", policy.AccessR, true},
		{"/etc", policy.AccessR, true},
		{"/etcx/passwd", 0, false},
		{"/var/log", 0, false},
		{"/", 0, false},
	}
	for _, c := range cases {
		m, ok := policy.MatchWhitelist(c.path, wl)
		if ok != c.ok || m != c.mask {
			t.Errorf("%s: got (%v,%v), want (%v,%v)", c.path, m, ok, c.mask, c.ok)
		}
	}
}
