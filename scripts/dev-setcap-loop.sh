#!/bin/bash
# Development script: Auto-set capabilities on Nexus helper binaries
# Run with: sudo ./scripts/dev-setcap-loop.sh
#
# Sets CAP_SYS_ADMIN on nexus-netns (network namespace create/delete),
# CAP_NET_ADMIN+CAP_SYS_ADMIN on nexus-cni-exec (CNI plugin capability wrapper),
# and CAP_NET_BIND_SERVICE on nexus-dns (bind port 53 for CoreDNS).
# nexus itself needs no special capabilities — all privileged operations
# are delegated to these helper binaries.
# Loops every 2 seconds to pick up rebuilds automatically.

set -euo pipefail

# Resolve project root relative to this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

# Handle Ctrl-C gracefully
trap 'echo -e "\nStopping capability auto-setter..."; exit 0' SIGINT SIGTERM

NETNS_HELPER="$BUILD_DIR/nexus-netns"
CNI_EXEC="$BUILD_DIR/nexus-cni-exec"
QUOTA_HELPER="$BUILD_DIR/nexus-quota"
BTRFS_HELPER="$BUILD_DIR/nexus-btrfs"
DNS_HELPER="$BUILD_DIR/nexus-dns"

echo "Starting capability auto-setter (Ctrl+C to stop)"
echo "Watching:"
echo "  $NETNS_HELPER  → CAP_SYS_ADMIN"
echo "  $CNI_EXEC      → CAP_NET_ADMIN,CAP_NET_RAW,CAP_SYS_ADMIN"
echo "  $QUOTA_HELPER  → CAP_SYS_ADMIN"
echo "  $BTRFS_HELPER  → CAP_SYS_ADMIN,CAP_FOWNER"
echo "  $DNS_HELPER    → CAP_NET_BIND_SERVICE"
echo "  $PROJECT_ROOT/.e2e-bin-* → E2E test binaries (same caps)"

set_caps_on_dir() {
    local dir="$1"
    [ -f "$dir/nexus-netns" ]    && setcap cap_sys_admin+ep "$dir/nexus-netns" 2>/dev/null || true
    [ -f "$dir/nexus-cni-exec" ] && setcap cap_net_admin,cap_net_raw,cap_sys_admin+ep "$dir/nexus-cni-exec" 2>/dev/null || true
    [ -f "$dir/nexus-quota" ]    && setcap cap_sys_admin+ep "$dir/nexus-quota" 2>/dev/null || true
    [ -f "$dir/nexus-btrfs" ]    && setcap cap_sys_admin,cap_fowner+ep "$dir/nexus-btrfs" 2>/dev/null || true
    [ -f "$dir/nexus-dns" ]      && setcap cap_net_bind_service+ep "$dir/nexus-dns" 2>/dev/null || true
}

while true; do
    # Set caps on build/ binaries.
    set_caps_on_dir "$BUILD_DIR"

    # Set caps on E2E test binaries (built to project root, not /tmp,
    # because /tmp is nosuid which silently ignores file capabilities).
    for e2e_dir in "$PROJECT_ROOT"/.e2e-bin-*; do
        [ -d "$e2e_dir" ] && set_caps_on_dir "$e2e_dir"
    done

    echo "[$(date +%H:%M:%S)] Capabilities set"
    sleep 2
done
