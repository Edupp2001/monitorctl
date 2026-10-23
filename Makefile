GO      ?= go
BINARY  ?= bin/monitorctl

.PHONY: all build test lint vet tidy build-bpf clean

all: build

build:
	$(GO) build -trimpath -ldflags "-X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)" -o $(BINARY) ./cmd/monitorctl

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

# build-bpf compiles the C BPF programs and regenerates the bpf2go bindings.
# Placeholder until Phase 3.
build-bpf:
	./scripts/build-bpf.sh

clean:
	rm -rf bin/