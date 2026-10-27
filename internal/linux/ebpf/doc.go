// Package ebpf loads and attaches the monitorctl BPF programs, drains the
// ringbuf, and manages bpffs-pinned links so network enforcement survives
// monitorctl crashes.
//
// Phase 3 ships filesystem observability (fs.bpf.c) via kprobes on the
// __x64_sys_* syscall wrappers. Tracepoints were rejected because
// perf_event_open delivery misses short-lived processes on some kernels
// (6.17 observed). Network (net.bpf.c) and memory-warn (mem.bpf.c) programs
// land in Phase 3.5.
//
// The generated bindings (fs_bpfel.go / fs_bpfel.o, and the big-endian
// variants) are produced by bpf2go; do not edit them by hand.
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -no-strip -cflags "-O2 -g -Wall -mcpu=v3 -fno-eliminate-unused-debug-types -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu" -type fs_event -type cgroup_stats fs bpf/fs.bpf.c
