// Package policy defines the monitorctl access model: scope, whitelist, and
// inode-based identity.
package policy

// Whitelist is the policy-side representation of the whitelist, after path
// resolution and target-binary auto-insertion.
//
// The three lists correspond 1:1 with the TOML sections of the same name and
// define positive permissions inside the cell. What happens *outside* the
// whitelist is determined by Scope, not by these lists.
type Whitelist struct {
	// AllowRead lists paths the target may only read.
	AllowRead []string
	// AllowWrite lists paths the target may read and write (no exec).
	AllowWrite []string
	// AllowAll lists paths the target may read, write and execute.
	AllowAll []string
}

// WithTarget returns a defensive copy of w with target appended to AllowAll
// (if not already present). Called by supervisor.Run so the initial
// execve(target) — which Landlock checks because the ruleset is applied
// before execve — succeeds even if the target's path is not listed in the
// TOML.
//
// Example:
//
//	wl := policy.Whitelist{AllowWrite: []string{"/tmp"}}
//	wl = wl.WithTarget("/bin/ls")
//	// wl.AllowAll == []string{"/bin/ls"}, wl.AllowWrite unchanged
func (w Whitelist) WithTarget(target string) Whitelist {
	out := Whitelist{
		AllowRead:  append([]string{}, w.AllowRead...),
		AllowWrite: append([]string{}, w.AllowWrite...),
		AllowAll:   append([]string{}, w.AllowAll...),
	}
	for _, p := range out.AllowAll {
		if p == target {
			return out
		}
	}
	out.AllowAll = append(out.AllowAll, target)
	return out
}
