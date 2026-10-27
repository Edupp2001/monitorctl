#!/usr/bin/env bash
# Build BPF C programs and generate Go bindings via bpf2go.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v clang >/dev/null; then
    echo "error: clang not found; install with: sudo apt install clang" >&2
    exit 1
fi
if [ ! -f /usr/include/bpf/bpf_helpers.h ]; then
    echo "error: libbpf headers not found; install with: sudo apt install libbpf-dev" >&2
    exit 1
fi

go generate ./internal/linux/ebpf/...
echo "BPF build OK."