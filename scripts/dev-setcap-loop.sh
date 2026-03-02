#!/bin/bash
# Development script: Auto-set capabilities on Nexus binaries
# Run with: sudo ./scripts/dev-setcap-loop.sh
#
# Sets CAP_NET_ADMIN on nexusd (bridge/veth/iptables) and
# CAP_SYS_ADMIN on nexus-netns (network namespace create/delete).
# Loops every 2 seconds to pick up rebuilds automatically.

set -euo pipefail

# Resolve project root relative to this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Handle Ctrl-C gracefully
trap 'echo -e "\nStopping capability auto-setter..."; exit 0' SIGINT SIGTERM

NEXUSD="$PROJECT_ROOT/nexusd"
HELPER="$PROJECT_ROOT/nexus-netns"

echo "Starting capability auto-setter (Ctrl+C to stop)"
echo "Watching:"
echo "  $NEXUSD    → CAP_NET_ADMIN"
echo "  $HELPER    → CAP_SYS_ADMIN"

while true; do
    if [ -f "$NEXUSD" ]; then
        setcap cap_net_admin+eip "$NEXUSD" 2>/dev/null || true
    fi
    if [ -f "$HELPER" ]; then
        setcap cap_sys_admin+eip "$HELPER" 2>/dev/null || true
    fi
    echo "[$(date +%H:%M:%S)] Capabilities set"
    sleep 2
done
