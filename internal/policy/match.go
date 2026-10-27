package policy

import (
	"path/filepath"
	"strings"
)

// AccessMask is a bitmask over read/write/exec.
type AccessMask uint8

const (
	// AccessR grants read access.
	AccessR AccessMask = 1 << 0
	// AccessW grants write access (which includes delete and rename).
	AccessW AccessMask = 1 << 1
	// AccessX grants exec access.
	AccessX AccessMask = 1 << 2
	// AccessRW is read+write.
	AccessRW = AccessR | AccessW
	// AccessRWX is read+write+exec.
	AccessRWX = AccessR | AccessW | AccessX
)

// MatchWhitelist returns the widest access mask granted to path by wl, and
// whether path is covered by any whitelist entry.
//
// Matching is string-prefix based with a "/" boundary check. Symlinks and
// target-side mount tricks are not resolved (documented limitation).
//
// Example:
//
//	mask, ok := policy.MatchWhitelist("/tmp/foo",
//	    policy.Whitelist{AllowWrite: []string{"/tmp"}})
//	// ok == true, mask == policy.AccessRW
func MatchWhitelist(path string, wl Whitelist) (AccessMask, bool) {
	path = filepath.Clean(path)
	for _, p := range wl.AllowAll {
		if isUnder(path, p) {
			return AccessRWX, true
		}
	}
	for _, p := range wl.AllowWrite {
		if isUnder(path, p) {
			return AccessRW, true
		}
	}
	for _, p := range wl.AllowRead {
		if isUnder(path, p) {
			return AccessR, true
		}
	}
	return 0, false
}

func isUnder(path, prefix string) bool {
	if path == prefix || prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return path[len(prefix)] == '/'
}
