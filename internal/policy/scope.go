package policy

import "fmt"

// Scope determines which operations are denied outside the whitelist.
//
//	scope=all    read + write + exec outside whitelist → EPERM (default)
//	scope=exec   exec outside whitelist → EPERM; read/write unrestricted
//	scope=write  write + exec outside whitelist → EPERM; read unrestricted
type Scope string

const (
	// ScopeAll denies read, write and exec outside the whitelist.
	ScopeAll Scope = "all"
	// ScopeExec denies only exec outside the whitelist.
	ScopeExec Scope = "exec"
	// ScopeWrite denies write and exec outside the whitelist.
	ScopeWrite Scope = "write"
)

// ParseScope converts a CLI string to a Scope.
//
// Example:
//
//	s, err := policy.ParseScope("all") // s == policy.ScopeAll, err == nil
func ParseScope(s string) (Scope, error) {
	switch Scope(s) {
	case ScopeAll, ScopeExec, ScopeWrite:
		return Scope(s), nil
	}
	return "", fmt.Errorf("invalid scope %q: must be all|exec|write", s)
}
