#!/usr/bin/env bash
# Placeholder until Phase 3. Will run:
#   clang -target bpf -O2 -g -c -o internal/linux/ebpf/bpf/fs.bpf.o \
#         internal/linux/ebpf/bpf/fs.bpf.c
# plus `go generate ./internal/linux/ebpf` (bpf2go).
set -euo pipefail
echo "build-bpf: not yet implemented (Phase 3)" >&2
exit 1