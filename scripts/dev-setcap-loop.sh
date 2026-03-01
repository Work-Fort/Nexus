#!/bin/bash
# Development script: Auto-set CAP_NET_ADMIN on the nexusd binary
# Run with: sudo ./scripts/dev-setcap-loop.sh
#
# This allows nexusd to create network namespaces and configure CNI
# without running as root. The capability is set every 2 seconds
# if the binary exists, so it picks up rebuilds automatically.

set -euo pipefail

# Resolve project root relative to this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Handle Ctrl-C gracefully
trap 'echo -e "\nStopping CAP_NET_ADMIN auto-setter..."; exit 0' SIGINT SIGTERM

BINARY="$PROJECT_ROOT/nexusd"

echo "Starting CAP_NET_ADMIN auto-setter (Ctrl+C to stop)"
echo "Watching for: $BINARY"

while true; do
    if [ -f "$BINARY" ]; then
        setcap cap_net_admin+eip "$BINARY" 2>/dev/null || true
        echo "[$(date +%H:%M:%S)] Set CAP_NET_ADMIN on $BINARY"
    fi
    sleep 2
done
