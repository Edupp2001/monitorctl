package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/Edupp2001/monitorctl/internal/policy"
)

// Access types emitted in fsEvent.AccessType.
const (
	AccessRead   = 0
	AccessWrite  = 1
	AccessExec   = 2
	AccessDelete = 3
	AccessRename = 4
)

// Violation is emitted for every event that is outside the whitelist and
// classified as either a warning or a violation under the active scope.
type Violation struct {
	Time       time.Time
	Scope      policy.Scope
	Category   string // "fs"
	Action     string // "warn"|"kill"
	Syscall    string
	AccessType string // "read"|"write"|"exec"|"delete"|"rename"
	Path       string
	Pid        uint32
	Tid        uint32
	Comm       string
	CgroupID   uint64
	Rule       string // "outside_whitelist"
}

// Config configures Load.
type Config struct {
	// CgroupPath is the target cgroup directory (used to compute cgroup_id
	// and populate target_cgroups map).
	CgroupPath string
	// Scope selects which accesses count as violations outside the whitelist.
	Scope policy.Scope
	// Whitelist provides the paths the target is allowed to touch.
	Whitelist policy.Whitelist
	// Log is the slog logger for reader lifecycle and unknown events.
	Log *slog.Logger
	// OnViolation is called from the reader goroutine for every event
	// classified as warning or violation. Must be goroutine-safe.
	OnViolation func(Violation)
	// OnOverflow is called when the ringbuf drops a violation event (fail-closed).
	OnOverflow func(dropped uint64)
}

// Loader owns the BPF objects, attached tracepoints, ringbuf reader, and two
// background goroutines (readLoop, statsLoop). Close stops everything.
type Loader struct {
	objs        *fsObjects
	links       []link.Link
	reader      *ringbuf.Reader
	log         *slog.Logger
	scope       policy.Scope
	whitelist   policy.Whitelist
	cgid        uint64
	targetPid   uint32
	onViolation func(Violation)
	onOverflow  func(uint64)
	stopCh      chan struct{}
	wg          sync.WaitGroup
	processed   atomic.Uint64
}

// Cgid returns the cgroup_id (stat.Ino) that monitorctl put in target_cgroups.
func (l *Loader) Cgid() uint64 { return l.cgid }

// Load loads fs.bpf.c, sets the scope variable, attaches tracepoints to the
// syscall tracepoints, inserts the cgroup_id into target_cgroups, and starts
// the ringbuf reader and stats poller.
//
// Example:
//
//	loader, err := ebpf.Load(&ebpf.Config{
//	    CgroupPath: "/sys/fs/cgroup/monitorctl/<uuid>",
//	    Scope:      policy.ScopeAll,
//	    Whitelist:  wl,
//	    Log:        log,
//	    OnViolation: func(v ebpf.Violation) { log.Warn("violation", ...) },
//	    OnOverflow:  func(d uint64) { grp.Kill() },
//	})
//	if err != nil { return err }
//	defer loader.Close()
func Load(cfg *Config) (*Loader, error) {
	spec, err := loadFs()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	var scopeVal uint8
	switch cfg.Scope {
	case policy.ScopeAll:
		scopeVal = 0
	case policy.ScopeExec:
		scopeVal = 1
	case policy.ScopeWrite:
		scopeVal = 2
	default:
		return nil, fmt.Errorf("unknown scope %q", cfg.Scope)
	}
	v, ok := spec.Variables["scope"]
	if !ok {
		return nil, errors.New("BPF program has no 'scope' variable")
	}
	if err := v.Set(scopeVal); err != nil {
		return nil, fmt.Errorf("set scope variable: %w", err)
	}

	var objs fsObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("LoadAndAssign: %w", err)
	}
	ok2 := false
	defer func() {
		if !ok2 {
			_ = objs.Close()
		}
	}()

	var st unix.Stat_t
	if err := unix.Stat(cfg.CgroupPath, &st); err != nil {
		return nil, fmt.Errorf("stat cgroup %s: %w", cfg.CgroupPath, err)
	}
	cgid := st.Ino

	var one uint8 = 1
	if err := objs.TargetCgroups.Put(cgid, &one); err != nil {
		return nil, fmt.Errorf("put target_cgroups: %w", err)
	}

	tp := []struct {
		cat, name string
		prog      *ebpf.Program
	}{
		{"syscalls", "sys_enter_openat", objs.TpOpenat},
		{"syscalls", "sys_enter_openat2", objs.TpOpenat2},
		{"syscalls", "sys_enter_open", objs.TpOpen},
		{"syscalls", "sys_enter_unlinkat", objs.TpUnlinkat},
		{"syscalls", "sys_enter_renameat2", objs.TpRenameat2},
		{"syscalls", "sys_enter_execve", objs.TpExecve},
	}
	var links []link.Link
	var nilProgs []string
	for _, t := range tp {
		if t.prog == nil {
			nilProgs = append(nilProgs, t.cat+"/"+t.name)
			continue
		}
		lnk, err := link.Tracepoint(t.cat, t.name, t.prog, nil)
		if err != nil {
			for _, l := range links {
				_ = l.Close()
			}
			return nil, fmt.Errorf("attach %s/%s: %w", t.cat, t.name, err)
		}
		links = append(links, lnk)
	}
	if len(nilProgs) > 0 {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, fmt.Errorf("BPF programs missing: %v", nilProgs)
	}
	if len(links) != len(tp) {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, fmt.Errorf("attached %d/%d tracepoints", len(links), len(tp))
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	l := &Loader{
		objs:        &objs,
		links:       links,
		reader:      rd,
		log:         cfg.Log,
		scope:       cfg.Scope,
		whitelist:   cfg.Whitelist,
		cgid:        cgid,
		onViolation: cfg.OnViolation,
		onOverflow:  cfg.OnOverflow,
		stopCh:      make(chan struct{}),
	}
	l.wg.Add(2)
	go l.readLoop()
	go l.statsLoop()

	ok2 = true
	return l, nil
}

// Close stops the reader and stats goroutines, detaches tracepoints, and
// releases BPF objects. Safe to call multiple times.
func (l *Loader) Close() error {
	close(l.stopCh)
	if l.reader != nil {
		_ = l.reader.Close()
	}
	l.wg.Wait()
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	l.links = nil
	if l.objs != nil {
		err := l.objs.Close()
		l.objs = nil
		return err
	}
	return nil
}

func (l *Loader) readLoop() {
	defer l.wg.Done()
	for {
		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			l.log.Warn("ringbuf read", "error", err.Error())
			continue
		}
		l.handleRecord(record.RawSample)
	}
}

func (l *Loader) statsLoop() {
	defer l.wg.Done()
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case <-t.C:
			l.checkStats()
		}
	}
}

func (l *Loader) checkStats() {
	st, err := l.Stats()
	if err != nil || st.ViolationsDropped == 0 {
		return
	}
	if l.onOverflow != nil {
		l.onOverflow(st.ViolationsDropped)
	}
	// Сброс: итерируем и обнуляем
	var key uint64
	var v fsCgroupStats
	it := l.objs.CgStats.Iterate()
	for it.Next(&key, &v) {
		if v.ViolationsDropped > 0 {
			v.ViolationsDropped = 0
			_ = l.objs.CgStats.Put(key, &v)
		}
	}
}

func (l *Loader) handleRecord(raw []byte) {
	var evt fsFsEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return
	}
	if os.Getenv("MONITORCTL_DEBUG") != "" {
		l.log.Info("event",
			"evt_cgid", evt.CgroupId,
			"expected_cgid", l.cgid,
			"match", evt.CgroupId == l.cgid,
			"comm", cstr(evt.Comm[:]),
			"path", cstr(evt.Path[:]))
	}
	l.processed.Add(1)

	comm := cstr(evt.Comm[:])

	// Ignore monitorctl's own syscalls during pre-exec pipeline. The child
	// enters the target cgroup at clone time (CLONE_INTO_CGROUP), so its
	// setrlimit/prctl/landlock/time.LoadLocation calls are visible to us.
	if comm == "exe" || comm == "monitorctl" {
		return
	}

	path := cstr(evt.Path[:])

	absPath, err := policy.ResolveEventPath(evt.Pid, evt.Dirfd, []byte(path))
	if err != nil {
		l.log.Debug("resolve failed",
			"pid", evt.Pid, "dirfd", evt.Dirfd, "path", path, "error", err.Error())
		return
	}

	if _, inWL := policy.MatchWhitelist(absPath, l.whitelist); inWL {
		return
	}

	access := int(evt.AccessType)
	class := classifyEvent(l.scope, access)
	if class == classPass {
		return
	}

	if l.onViolation == nil {
		return
	}
	l.onViolation(Violation{
		Time:       time.Now(),
		Scope:      l.scope,
		Category:   "fs",
		Action:     actionString(class),
		Syscall:    syscallName(evt.SyscallNr),
		AccessType: accessName(access),
		Path:       absPath,
		Pid:        evt.Pid,
		Tid:        evt.Tid,
		Comm:       comm,
		CgroupID:   evt.CgroupId,
		Rule:       "outside_whitelist",
	})
}

func cstr(b []uint8) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

type eventClass int

const (
	classPass eventClass = iota
	classWarn
	classViolation
)

func classifyEvent(scope policy.Scope, access int) eventClass {
	switch scope {
	case policy.ScopeAll:
		return classViolation
	case policy.ScopeExec:
		if access == AccessExec {
			return classViolation
		}
		return classPass
	case policy.ScopeWrite:
		if access == AccessRead {
			return classWarn
		}
		return classViolation
	}
	return classPass
}

func actionString(c eventClass) string {
	switch c {
	case classWarn:
		return "warn"
	case classViolation:
		return "kill"
	}
	return "pass"
}

func syscallName(nr uint32) string {
	switch nr {
	case 2:
		return "open"
	case 257:
		return "openat"
	case 437:
		return "openat2"
	case 263:
		return "unlinkat"
	case 316:
		return "renameat2"
	case 59:
		return "execve"
	}
	return fmt.Sprintf("syscall_%d", nr)
}

func accessName(a int) string {
	switch a {
	case AccessRead:
		return "read"
	case AccessWrite:
		return "write"
	case AccessExec:
		return "exec"
	case AccessDelete:
		return "delete"
	case AccessRename:
		return "rename"
	}
	return "unknown"
}

// Drain waits until all events emitted by the BPF program have been consumed
// by the reader goroutine, or until timeout.
//
// The BPF program bumps cg_stats.events_emitted before ringbuf_submit for
// every event; the reader bumps Loader.processed for every event it pops.
// Drain polls until processed >= emitted, which is the exact moment the
// reader has caught up.
//
// Call after target exit and before Close. Without it, events emitted in the
// last few milliseconds before target exit are lost: ringbuf.Reader.Close()
// does not drain the buffer.
//
// Example:
//
//	loader.Drain(500 * time.Millisecond)
//	loader.Close()
func (l *Loader) Drain(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		st, _ := l.Stats() // ← агрегация, устойчива к cgid mismatch
		if l.processed.Load() >= st.EventsEmitted {
			return
		}
		if time.Now().After(deadline) {
			l.log.Warn("drain timeout",
				"emitted", st.EventsEmitted,
				"processed", l.processed.Load())
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Warmup blocks until the tracepoint infrastructure is confirmed active,
// or until timeout. It issues test openat() calls in a loop and polls
// seen_pids for our own pid. This eliminates the static-key propagation
// race between link.Tracepoint returning and the syscall_enter tracepoint
// being enabled on all CPUs.
//
// Also serves as a diagnostic: on timeout, the returned error includes the
// full seen_pids snapshot (if any) to distinguish "tracepoint never fires"
// from "fires only for other processes".
//
// Call from main.go immediately after ebpf.Load(), before supervisor.Run().
//
// Example:
//
//	if err := loader.Warmup(500 * time.Millisecond); err != nil {
//	    log.Warn("eBPF warmup failed", "error", err.Error())
//	}
func (l *Loader) Warmup(timeout time.Duration) error {
	myPid := uint32(os.Getpid())
	deadline := time.Now().Add(timeout)
	var lastSeen map[uint32]uint64
	for time.Now().Before(deadline) {
		f, err := os.Open("/dev/null")
		if err == nil {
			_ = f.Close()
		}
		time.Sleep(2 * time.Millisecond)
		lastSeen = l.DumpSeen()
		if _, ok := lastSeen[myPid]; ok {
			return nil
		}
	}
	return fmt.Errorf("warmup timeout after %v: tracepoint did not fire for pid %d; seen_pids has %d entries: %v",
		timeout, myPid, len(lastSeen), lastSeen)
}

// Stats returns aggregated cgroup_stats across every key in the map.
//
// Aggregation (rather than Lookup(l.cgid)) is required because the BPF
// program's cg_stats key is bpf_get_current_cgroup_id(), which on some
// kernels does not equal our stat(dir).Ino. The values are semantically
// per-target because only target events reach the program (via
// check_target), so summing is correct.
func (l *Loader) Stats() (fsCgroupStats, error) {
	var total fsCgroupStats
	var key uint64
	var val fsCgroupStats
	it := l.objs.CgStats.Iterate()
	for it.Next(&key, &val) {
		total.EventsEmitted += val.EventsEmitted
		total.WarningsDropped += val.WarningsDropped
		total.ViolationsDropped += val.ViolationsDropped
	}
	if err := it.Err(); err != nil {
		return total, err
	}
	return total, nil
}

// Processed returns the number of events the reader goroutine has consumed
// from the ringbuf since Load.
func (l *Loader) Processed() uint64 {
	return l.processed.Load()
}

// DumpCgStats iterates cg_stats and returns every (cgroup_id, stats) pair
// currently present. Used for diagnostics when Loader.Stats() returns
// ErrKeyNotExist: if an unexpected cgroup_id appears with events_emitted > 0,
// the child landed in the wrong cgroup.
func (l *Loader) DumpCgStats() map[uint64]fsCgroupStats {
	out := map[uint64]fsCgroupStats{}
	var key uint64
	var val fsCgroupStats
	it := l.objs.CgStats.Iterate()
	for it.Next(&key, &val) {
		out[key] = val
	}
	return out
}

// UpdateCgid records the child's actual cgroup id and pid for BPF filtering.
// Called from supervisor.Run's OnCgroupReady before the child is unblocked.
//
// Two maps are maintained:
//   - target_cgroups[cgid] = 1   (primary filter)
//   - target_pids[pid]    = 1    (fallback for kernels where
//     bpf_get_current_cgroup_id() disagrees
//     with stat(dir).Ino)
func (l *Loader) UpdateCgid(newCgid uint64, pid uint32) error {
	var one uint8 = 1
	if newCgid != l.cgid {
		_ = l.objs.TargetCgroups.Delete(l.cgid)
		if err := l.objs.TargetCgroups.Put(newCgid, &one); err != nil {
			return fmt.Errorf("put target_cgroups %d: %w", newCgid, err)
		}
		l.cgid = newCgid
	}
	if pid != 0 {
		if err := l.objs.TargetPids.Put(pid, &one); err != nil {
			return fmt.Errorf("put target_pids %d: %w", pid, err)
		}
		l.targetPid = pid
	}
	return nil
}

// DumpSeen returns a snapshot of every (pid, cgid) that hit any tracepoint
// since Load. Used to diagnose "tracepoint fires but check_target returns 0".
func (l *Loader) DumpSeen() map[uint32]uint64 {
	out := map[uint32]uint64{}
	var k uint32
	var v uint64
	it := l.objs.SeenPids.Iterate()
	for it.Next(&k, &v) {
		out[k] = v
	}
	return out
}
