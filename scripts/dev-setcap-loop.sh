#!/bin/bash
# Development script: Auto-set CAP_NET_ADMIN on nexusd binary
# Run with: sudo ./scripts/dev-setcap-loop.sh
#
# This allows automatic testing without sudo after each build.
# The capability is set every 2 seconds if the binary exists.

set -euo pipefail

BINARY_PATHS=(
    "target/debug/nexusd"
    "target/release/nexusd"
)

echo "Starting CAP_NET_ADMIN auto-setter (Ctrl+C to stop)"
echo "Watching for nexusd binaries..."

while true; do
    for binary in "${BINARY_PATHS[@]}"; do
        if [ -f "$binary" ]; then
            setcap cap_net_admin+ep "$binary" 2>/dev/null || true
            echo "[$(date +%H:%M:%S)] Set CAP_NET_ADMIN on $binary"
        fi
    done
    sleep 2
done
