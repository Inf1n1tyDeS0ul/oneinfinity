#!/usr/bin/env bash
# ebpf_shell.sh — Enter the eBPF development container.
# Usage: ./scripts/ebpf_shell.sh [command]
# With no args, drops into an interactive shell.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
IMAGE="oneinfinity-ebpf-dev:latest"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building eBPF dev image..."
  docker build -f "$SCRIPT_DIR/src/ebpf/Dockerfile.dev" -t "$IMAGE" "$SCRIPT_DIR/src/ebpf"
fi

exec docker run --rm -it \
  --privileged \
  -v "$SCRIPT_DIR:/workspace:ro" \
  -v "$SCRIPT_DIR/src/ebpf/build:/workspace/src/ebpf/build" \
  "$IMAGE" \
  "${@:-bash}"
