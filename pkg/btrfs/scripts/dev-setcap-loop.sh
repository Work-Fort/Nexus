#!/bin/bash
# Development script: Auto-set capabilities on btrfs test binary
# Run with: sudo ./pkg/btrfs/scripts/dev-setcap-loop.sh
#
# Sets CAP_SYS_ADMIN (for quota ioctls, btrfs send/receive) and
# CAP_FOWNER (btrfs-progs opens mount point with O_NOATIME).
# This allows automatic testing without sudo after each build.
# The capabilities are set every 2 seconds if the binary exists.

set -euo pipefail

# Resolve project root relative to this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Handle Ctrl-C gracefully
trap 'echo -e "\nStopping capability auto-setter..."; exit 0' SIGINT SIGTERM

BINARY_PATHS=(
    "$PROJECT_ROOT/pkg/btrfs/btrfs.test"
)

echo "Starting capability auto-setter (Ctrl+C to stop)"
echo "Watching for btrfs test binary..."

while true; do
    for binary in "${BINARY_PATHS[@]}"; do
        if [ -f "$binary" ]; then
            setcap cap_sys_admin,cap_fowner+ep "$binary" 2>/dev/null || true
            echo "[$(date +%H:%M:%S)] Set CAP_SYS_ADMIN,CAP_FOWNER on $binary"
        fi
    done
    sleep 2
done
