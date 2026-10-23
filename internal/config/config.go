// Package config handles loading and validating the monitorctl whitelist
// configuration file (TOML).
//
// The whitelist has three sections, each granting positive permissions on a
// set of paths inside the cell:
//
//	allow_read  = ["/etc/passwd", ...]      # read only
//	allow_write = ["/tmp", ...]             # read + write
//	allow_all   = ["/bin/ls", ...]          # read + write + exec
//
// What happens *outside* the whitelist is determined by --scope, not by these
// lists. See internal/policy for the scope model.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/BurntSushi/toml"
)

// Whitelist is the parsed representation of a whitelist.toml file.
type Whitelist struct {
	// Path records the source file for diagnostics and reload checks.
	Path string `toml:"-"`

	// AllowRead lists paths the target may only read.
	AllowRead []string `toml:"allow_read"`

	// AllowWrite lists paths the target may read and write (no exec).
	AllowWrite []string `toml:"allow_write"`

	// AllowAll lists paths the target may read, write and execute.
	AllowAll []string `toml:"allow_all"`
}

// Load reads, parses and structurally validates the whitelist file at path.
//
// Load does not verify that paths exist on disk — call ValidatePaths for that.
// Per ARCHITECTURE.md a missing path is a warning, not a fatal error.
//
// Example:
//
//	wl, err := config.Load("examples/wl-test.toml")
//	if err != nil { return err }
func Load(path string) (*Whitelist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read whitelist %q: %w", path, err)
	}
	var wl Whitelist
	if err := toml.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("parse whitelist %q: %w", path, err)
	}
	wl.Path = path
	if err := wl.validate(); err != nil {
		return nil, err
	}
	return &wl, nil
}

// validate enforces structural invariants: every path absolute and non-empty,
// no path present in more than one list, and at least one path configured.
func (w *Whitelist) validate() error {
	seen := map[string]string{}
	check := func(cat string, paths []string) error {
		for _, p := range paths {
			if p == "" {
				return fmt.Errorf("whitelist %q: empty path in %s", w.Path, cat)
			}
			if p[0] != '/' {
				return fmt.Errorf("whitelist %q: path %q in %s is not absolute", w.Path, p, cat)
			}
			if prev, dup := seen[p]; dup {
				return fmt.Errorf("whitelist %q: path %q listed in both %s and %s",
					w.Path, p, prev, cat)
			}
			seen[p] = cat
		}
		return nil
	}
	if err := check("allow_read", w.AllowRead); err != nil {
		return err
	}
	if err := check("allow_write", w.AllowWrite); err != nil {
		return err
	}
	if err := check("allow_all", w.AllowAll); err != nil {
		return err
	}
	if len(seen) == 0 {
		return fmt.Errorf("whitelist %q: no paths configured", w.Path)
	}
	return nil
}

// EnsurePaths creates missing directories listed in AllowWrite and AllowAll
// (mode 0755, owned by the caller). AllowRead entries are not created — they
// may point at files.
//
// Existing regular files at a listed path are not treated as errors: the
// admin may legitimately whitelist a single file.
//
// Note: when --drop-privs=yes is used, created directories are owned by root,
// not the target uid. The README instructs the admin to chown them (see
// ARCHITECTURE.md §Privilege drop).
//
// Example:
//
//	for _, w := range wl.EnsurePaths() { log.Warn("whitelist", "detail", w) }
func (w *Whitelist) EnsurePaths() []string {
	var warnings []string
	for _, p := range append(append([]string{}, w.AllowWrite...), w.AllowAll...) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			if isExistingNonDir(p) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("ensure whitelist path %q: %v", p, err))
		}
	}
	return warnings
}

func isExistingNonDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// ValidatePaths returns one warning per configured path that cannot be
// stat()'d for a reason other than "does not exist". Never returns an error.
//
// Example:
//
//	for _, w := range wl.ValidatePaths() { log.Warn("whitelist", "detail", w) }
func (w *Whitelist) ValidatePaths() []string {
	var warnings []string
	for _, p := range w.allPaths() {
		if _, err := os.Stat(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			warnings = append(warnings, fmt.Sprintf("whitelist path %q: %v", p, err))
		}
	}
	return warnings
}

// allPaths returns all configured paths in a single slice, without aliasing
// any of the three source slices.
func (w *Whitelist) allPaths() []string {
	out := make([]string, 0, len(w.AllowRead)+len(w.AllowWrite)+len(w.AllowAll))
	out = append(out, w.AllowRead...)
	out = append(out, w.AllowWrite...)
	out = append(out, w.AllowAll...)
	return out
}
