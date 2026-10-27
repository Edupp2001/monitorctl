// SPDX-License-Identifier: GPL-2.0
//
// monitorctl fs.bpf.c — filesystem observability via tracepoints.
//
// Attached to sys_enter_* tracepoints for open/openat/openat2/unlinkat/
// renameat2/execve. Filters by cgroup_id against target_cgroups map.
// Emits events to a ringbuf; userspace resolves paths against the inode
// whitelist and decides warn vs violation.
//
// Rate-limit: open O_RDONLY only, 100/sec per cgroup_id, only when scope
// is exec or write (reads are unrestricted outside whitelist there, so they
// are warnings not violations). scope=all has no rate-limit for reads —
// floods hit ringbuf overflow → userspace kills the cgroup.
//
// Ringbuf overflow: if reserve fails for a violation event (write, unlink,
// rename, exec), increment cg_stats[cgid].violations_dropped. Userspace
// polls cg_stats and calls cgroup.kill when >0 (fail-closed).

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH  128
#define MAX_COMM  16

#define SCOPE_ALL   0
#define SCOPE_EXEC  1
#define SCOPE_WRITE 2

#define RATE_LIMIT_MAX 100

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

#ifndef O_ACCMODE
#define O_ACCMODE  00000003
#define O_RDONLY   00000000
#define O_WRONLY   00000001
#define O_RDWR     00000002
#define O_CREAT    00000100
#define O_TRUNC    00001000
#define O_APPEND   00002000
#endif

enum event_type {
    FS_OPEN   = 0,
    FS_UNLINK = 1,
    FS_RENAME = 2,
    FS_EXEC   = 3,
};

enum access_type {
    FS_ACCESS_READ   = 0,
    FS_ACCESS_WRITE  = 1,
    FS_ACCESS_EXEC   = 2,
    FS_ACCESS_DELETE = 3,
    FS_ACCESS_RENAME = 4,
};

struct trace_event_raw_sys_enter {
    __u64 unused;
    long  id;
    unsigned long args[6];
};

struct open_how {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

struct fs_event {
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 syscall_nr;
    __s32 dirfd;
    __s32 dirfd2;
    __u32 flags;
    __u32 flags2;
    __u32 path_len;
    __u32 path2_len;
    __u8  comm[MAX_COMM];
    __u8  event_type;
    __u8  access_type;
    __u8  reserved[2];
    __u8  path[MAX_PATH];
    __u8  path2[MAX_PATH];
};
// Force BTF emission: clang 18 elides types only reached via void*
// (bpf_ringbuf_reserve returns void*).
__attribute__((used)) static struct fs_event __btf_force_fs_event;

struct rate_info {
    __u64 window_sec;
    __u32 count;
    __u32 _reserved;
};

struct cgroup_stats {
    __u64 events_emitted;
    __u64 warnings_dropped;
    __u64 violations_dropped;
};

// scope is set by userspace before load via spec.Variables["scope"].
const volatile __u8 scope = SCOPE_ALL;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 1024);
} target_cgroups SEC(".maps");
 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} target_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct rate_info);
    __uint(max_entries, 1024);
} warn_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct cgroup_stats);
    __uint(max_entries, 1024);
} cg_stats SEC(".maps");

// Debug: log every (pid, cgid) that hits the tracepoint, regardless of
// check_target. Drained by Go in the "eBPF stats" log line.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} seen_pids SEC(".maps");

static __always_inline void log_seen(__u64 cgid)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&seen_pids, &pid, &cgid, BPF_ANY);
}
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1 MiB
} events SEC(".maps");

static __always_inline int check_target(__u64 *cgid_out)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *v = bpf_map_lookup_elem(&target_cgroups, &cgid);
    if (v) {
        *cgid_out = cgid;
        return 1;
    }
    // Fallback: some kernels intermittently return a stale/incorrect value
    // from bpf_get_current_cgroup_id() vs stat(dir).Ino. PID match covers
    // the target itself (no descendants — documented limitation).
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *p = bpf_map_lookup_elem(&target_pids, &pid);
    if (p) {
        *cgid_out = cgid;
        return 1;
    }
    return 0;
}

static __always_inline int is_rate_limited(__u64 cgid)
{
    __u64 now_sec = bpf_ktime_get_ns() / 1000000000ULL;
    struct rate_info *ri = bpf_map_lookup_elem(&warn_rate, &cgid);
    struct rate_info init = { .window_sec = now_sec, .count = 1 };
    if (!ri) {
        bpf_map_update_elem(&warn_rate, &cgid, &init, BPF_NOEXIST);
        return 0;
    }
    if (ri->window_sec != now_sec) {
        ri->window_sec = now_sec;
        ri->count = 1;
        return 0;
    }
    if (ri->count >= RATE_LIMIT_MAX)
        return 1;
    __sync_fetch_and_add(&ri->count, 1);
    return 0;
}

static __always_inline void bump_dropped(__u64 cgid, int is_warn)
{
    struct cgroup_stats *st = bpf_map_lookup_elem(&cg_stats, &cgid);
    struct cgroup_stats init = {
        .warnings_dropped   = is_warn ? 1 : 0,
        .violations_dropped = is_warn ? 0 : 1,
    };
    if (!st) {
        bpf_map_update_elem(&cg_stats, &cgid, &init, BPF_NOEXIST);
        return;
    }
    if (is_warn)
        __sync_fetch_and_add(&st->warnings_dropped, 1);
    else
        __sync_fetch_and_add(&st->violations_dropped, 1);
}

static __always_inline void bump_emitted(__u64 cgid)
{
    struct cgroup_stats *st = bpf_map_lookup_elem(&cg_stats, &cgid);
    struct cgroup_stats init = { .events_emitted = 1 };
    if (!st) {
        bpf_map_update_elem(&cg_stats, &cgid, &init, BPF_NOEXIST);
        return;
    }
    __sync_fetch_and_add(&st->events_emitted, 1);
}

static __always_inline struct fs_event *reserve_event(__u64 cgid)
{
    struct fs_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;
    __builtin_memset(e, 0, sizeof(*e));
    e->cgroup_id = cgid;
    __u64 pidtgid = bpf_get_current_pid_tgid();
    e->pid = pidtgid >> 32;
    e->tid = (__u32)pidtgid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

static __always_inline __u32 read_user_str(__u8 *dst, __u32 maxlen, __u64 uptr)
{
    if (!uptr)
        return 0;
    long n = bpf_probe_read_user_str(dst, maxlen, (void *)uptr);
    return n > 0 ? (__u32)n : 0;
}
static __always_inline int flags_to_access(__u32 flags)
{
    int acc = flags & O_ACCMODE;
    if (acc == O_WRONLY || acc == O_RDWR)
        return FS_ACCESS_WRITE;
    if (flags & (O_CREAT | O_TRUNC | O_APPEND))
        return FS_ACCESS_WRITE;
    return FS_ACCESS_READ;
}

// Reads are warnings only in exec/write scope; in scope=all they are
// violations and must not be dropped silently.
static __always_inline int should_skip_read(__u64 cgid)
{
    if (scope == SCOPE_ALL)
        return 0;
    return is_rate_limited(cgid);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    log_seen(bpf_get_current_cgroup_id());
    __u64 cgid;
    if (!check_target(&cgid))
        return 0;

    __s32 dirfd = (__s32)ctx->args[0];
    __u64 fname = ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    int access = flags_to_access(flags);
    int is_warn = (access == FS_ACCESS_READ);

    if (is_warn && should_skip_read(cgid)) {
        bump_dropped(cgid, 1);
        return 0;
    }
    struct fs_event *e = reserve_event(cgid);
    if (!e) {
        bump_dropped(cgid, is_warn);
        return 0;
    }
    e->event_type = FS_OPEN;
    e->access_type = (__u8)access;
    e->syscall_nr = 257;  // __NR_openat (x86_64)
    e->dirfd = dirfd;
    e->dirfd2 = AT_FDCWD;
    e->flags = flags;
    e->path_len = read_user_str(e->path, MAX_PATH, fname);
    bump_emitted(cgid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct trace_event_raw_sys_enter *ctx)
{
    log_seen(bpf_get_current_cgroup_id());
    __u64 cgid;
    if (!check_target(&cgid))
        return 0;

    __s32 dirfd = (__s32)ctx->args[0];
    __u64 fname = ctx->args[1];
    __u64 howp = ctx->args[2];
    struct open_how how = {};
    __u32 flags = 0;
    if (howp) {
        if (bpf_probe_read_user(&how, sizeof(how), (void *)howp) != 0)
            flags = O_WRONLY;  // conservative: treat as write
        else
            flags = (__u32)how.flags;
    }
    int access = flags_to_access(flags);
    int is_warn = (access == FS_ACCESS_READ);

    if (is_warn && should_skip_read(cgid)) {
        bump_dropped(cgid, 1);
        return 0;
    }
    struct fs_event *e = reserve_event(cgid);
    if (!e) {
        bump_dropped(cgid, is_warn);
        return 0;
    }
    e->event_type = FS_OPEN;
    e->access_type = (__u8)access;
    e->syscall_nr = 437;  // __NR_openat2 (x86_64)
    e->dirfd = dirfd;
    e->dirfd2 = AT_FDCWD;
    e->flags = flags;
    e->path_len = read_user_str(e->path, MAX_PATH, fname);
    bump_emitted(cgid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tp_open(struct trace_event_raw_sys_enter *ctx)
{
    log_seen(bpf_get_current_cgroup_id());
    __u64 cgid;
    if (!check_target(&cgid))
        return 0;

    __u64 fname = ctx->args[0];
    __u32 flags = (__u32)ctx->args[1];
    int access = flags_to_access(flags);
    int is_warn = (access == FS_ACCESS_READ);

    if (is_warn && should_skip_read(cgid)) {
        bump_dropped(cgid, 1);
        return 0;
    }
    struct fs_event *e = reserve_event(cgid);
    if (!e) {
        bump_dropped(cgid, is_warn);
        return 0;
    }
    e->event_type = FS_OPEN;
    e->access_type = (__u8)access;
    e->syscall_nr = 2;  // __NR_open (x86_64)
    e->dirfd = AT_FDCWD;
    e->dirfd2 = AT_FDCWD;
    e->flags = flags;
    e->path_len = read_user_str(e->path, MAX_PATH, fname);
    bump_emitted(cgid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    log_seen(bpf_get_current_cgroup_id());
    __u64 cgid;
    if (!check_target(&cgid))
        return 0;

    __s32 dirfd = (__s32)ctx->args[0];
    __u64 fname = ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];

    struct fs_event *e = reserve_event(cgid);
    if (!e) {
        bump_dropped(cgid, 0);
        return 0;
    }
    e->event_type = FS_UNLINK;
    e->access_type = FS_ACCESS_DELETE;
    e->syscall_nr = 263;  // __NR_unlinkat (x86_64)
    e->dirfd = dirfd;
    e->dirfd2 = AT_FDCWD;
    e->flags = flags;
    e->path_len = read_user_str(e->path, MAX_PATH, fname);
    bump_emitted(cgid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    log_seen(bpf_get_current_cgroup_id());
    __u64 cgid;
    if (!check_target(&cgid))
        return 0;

    __s32 odfd = (__s32)ctx->args[0];
    __u64 oname = ctx->args[1];
    __s32 ndfd = (__s32)ctx->args[2];
    __u64 nname = ctx->args[3];
    __u32 flags = (__u32)ctx->args[4];

    struct fs_event *e = reserve_event(cgid);
    if (!e) {
        bump_dropped(cgid, 0);
        return 0;
    }
    e->event_type = FS_RENAME;
    e->access_type = FS_ACCESS_RENAME;
    e->syscall_nr = 316;  // __NR_renameat2 (x86_64)
    e->dirfd = odfd;
    e->dirfd2 = ndfd;
    e->flags = flags;
    e->path_len = read_user_str(e->path, MAX_PATH, oname);
    e->path2_len = read_user_str(e->path2, MAX_PATH, nname);
    bump_emitted(cgid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    log_seen(bpf_get_current_cgroup_id());
    __u64 cgid;
    if (!check_target(&cgid))
        return 0;

    __u64 fname = ctx->args[0];

    struct fs_event *e = reserve_event(cgid);
    if (!e) {
        bump_dropped(cgid, 0);
        return 0;
    }
    e->event_type = FS_EXEC;
    e->access_type = FS_ACCESS_EXEC;
    e->syscall_nr = 59;  // __NR_execve (x86_64)
    e->dirfd = AT_FDCWD;
    e->dirfd2 = AT_FDCWD;
    e->path_len = read_user_str(e->path, MAX_PATH, fname);
    bump_emitted(cgid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";