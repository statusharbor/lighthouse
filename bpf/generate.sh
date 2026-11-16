#!/bin/sh
# Regenerates the committed bpf2go output (internal/ebpf/**/*_bpfel.{go,o})
# in a pinned image so every machine and CI produce identical objects.
# CI runs this and fails on a diff (docs/eBPF/01-foundation.md, criterion 1).
set -eu
IMAGE=golang:1.26.2-bookworm
cd "$(dirname "$0")/.."
exec docker run --rm -v "$PWD":/src -w /src -e GOWORK=off -e GOFLAGS=-mod=mod "$IMAGE" sh -c '
	apt-get update -qq >/dev/null &&
	apt-get install -y -qq --no-install-recommends clang llvm libbpf-dev >/dev/null &&
	go generate ./internal/ebpf/...'
