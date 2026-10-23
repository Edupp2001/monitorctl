// Package landlock wraps Landlock LSM syscalls.
package landlock

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/Edupp2001/monitorctl/internal/policy"
)

const (
	landlockCreateRulesetVersionFlag = 1 << 0
	landlockRulePathBeneath          = 1

	accessExecute    uint64 = 1 << 0
	accessWriteFile  uint64 = 1 << 1
	accessReadFile   uint64 = 1 << 2
	accessReadDir    uint64 = 1 << 3
	accessRemoveDir  uint64 = 1 << 4
	accessRemoveFile uint64 = 1 << 5
	accessMakeChar   uint64 = 1 << 6
	accessMakeDir    uint64 = 1 << 7
	accessMakeReg    uint64 = 1 << 8
	accessMakeSock   uint64 = 1 << 9
	accessMakeFifo   uint64 = 1 << 10
	accessMakeBlock  uint64 = 1 << 11
	accessMakeSym    uint64 = 1 << 12
	accessRefer      uint64 = 1 << 13 // ABI 2+
	accessTruncate   uint64 = 1 << 14 // ABI 3+
)

// Ruleset is an opaque handle to a Landlock ruleset fd.
type Ruleset struct{ fd int }

// ABI returns the kernel Landlock ABI version.
func ABI() (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		uintptr(landlockCreateRulesetVersionFlag))
	if errno != 0 {
		return 0, fmt.Errorf("landlock_create_ruleset(VERSION): %w", errno)
	}
	return int(r), nil
}

// NewRuleset builds a ruleset under the given scope. handledMask(scope)
// determines which rights are restricted at all; each whitelist category
// grants the intersection of its natural mask with the handled mask.
//
// Returns one warning string per configured list that becomes a no-op under
// the chosen scope (e.g. allow_read in scope=exec).
//
// Example:
//
//	rs, warns, err := landlock.NewRuleset(policy.ScopeAll, wl)
//	if err != nil { return err }
//	for _, w := range warns { log.Warn("landlock", "detail", w) }
func NewRuleset(scope policy.Scope, wl policy.Whitelist) (*Ruleset, []string, error) {
	abi, err := ABI()
	if err != nil {
		return nil, nil, err
	}
	h := handledMask(scope, abi)
	if h == 0 {
		return nil, nil, fmt.Errorf("landlock: scope %q has empty handled mask", scope)
	}

	attr := struct{ HandledAccessFS uint64 }{HandledAccessFS: h}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return nil, nil, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	rs := &Ruleset{fd: int(fd)}
	ok := false
	defer func() {
		if !ok {
			_ = rs.Close()
		}
	}()

	r := readAccess(abi)
	w := writeAccess(abi)
	e := accessExecute

	maskAll := (r | w | e) & h
	maskWrite := (r | w) & h
	maskRead := r & h

	var warnings []string
	if len(wl.AllowRead) > 0 && maskRead == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"allow_read entries (%d) have no effect in scope=%s (reads are unrestricted outside whitelist)",
			len(wl.AllowRead), scope))
	}
	if len(wl.AllowWrite) > 0 && maskWrite == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"allow_write entries (%d) have no effect in scope=%s (writes are unrestricted outside whitelist)",
			len(wl.AllowWrite), scope))
	}

	add := func(paths []string, mask uint64, cat string) {
		if mask == 0 {
			return
		}
		for _, p := range paths {
			if err := rs.addPathBeneath(p, mask); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s %q: %v", cat, p, err))
			}
		}
	}
	add(wl.AllowAll, maskAll, "allow_all")
	add(wl.AllowWrite, maskWrite, "allow_write")
	add(wl.AllowRead, maskRead, "allow_read")

	ok = true
	return rs, warnings, nil
}

func (r *Ruleset) addPathBeneath(path string, allowed uint64) error {
	pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer unix.Close(pfd)

	var buf [12]byte
	binary.LittleEndian.PutUint64(buf[0:8], allowed)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(pfd))

	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(r.fd), landlockRulePathBeneath,
		uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule (mask=0x%x): %w", allowed, errno)
	}
	return nil
}

// FD returns the underlying file descriptor.
func (r *Ruleset) FD() int { return r.fd }

// Close releases the ruleset fd. Safe to call multiple times.
func (r *Ruleset) Close() error {
	if r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}

// RestrictSelf applies rulesetFD to the calling thread. Must be preceded by
// prctl.SetNoNewPrivs.
func RestrictSelf(rulesetFD int) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFD), 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

// handledMask returns the rights restricted by the ruleset under scope.
func handledMask(scope policy.Scope, abi int) uint64 {
	r := readAccess(abi)
	w := writeAccess(abi)
	e := accessExecute
	switch scope {
	case policy.ScopeAll:
		return r | w | e
	case policy.ScopeExec:
		return e
	case policy.ScopeWrite:
		return w | e
	}
	return 0
}

func readAccess(int) uint64 { return accessReadFile | accessReadDir }

func writeAccess(abi int) uint64 {
	m := accessWriteFile | accessRemoveFile | accessRemoveDir |
		accessMakeChar | accessMakeDir | accessMakeReg | accessMakeSock |
		accessMakeFifo | accessMakeBlock | accessMakeSym
	if abi >= 2 {
		m |= accessRefer
	}
	if abi >= 3 {
		m |= accessTruncate
	}
	return m
}
