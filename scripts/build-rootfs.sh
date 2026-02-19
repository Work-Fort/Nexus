#!/usr/bin/env bash
# nexus/scripts/build-rootfs.sh
#
# Build a minimal Alpine rootfs ext4 image for Firecracker VMs.
# No root required — uses mke2fs -d to create the ext4 image from a directory.
#
# Dependencies: curl, tar, mke2fs (e2fsprogs)
#
# Usage:
#   ./scripts/build-rootfs.sh [--output PATH] [--size-mb N] [--alpine-version X.Y] [--alpine-patch Z]
#
# Defaults:
#   --output:          ./artifacts/rootfs.ext4
#   --size-mb:         512
#   --alpine-version:  3.23
#   --alpine-patch:    3

set -euo pipefail

# --- Defaults ---
OUTPUT="./artifacts/rootfs.ext4"
SIZE_MB=512
ALPINE_VERSION="3.23"
ALPINE_PATCH="3"

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)       OUTPUT="$2"; shift 2 ;;
        --size-mb)      SIZE_MB="$2"; shift 2 ;;
        --alpine-version) ALPINE_VERSION="$2"; shift 2 ;;
        --alpine-patch) ALPINE_PATCH="$2"; shift 2 ;;
        --force)        FORCE=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--output PATH] [--size-mb N] [--alpine-version X.Y] [--alpine-patch Z] [--force]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

ALPINE_FULL="${ALPINE_VERSION}.${ALPINE_PATCH}"
TARBALL_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/x86_64/alpine-minirootfs-${ALPINE_FULL}-x86_64.tar.gz"

# --- Preflight checks ---
for cmd in curl tar mke2fs; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: required command '$cmd' not found."
        echo "  Install e2fsprogs for mke2fs."
        exit 1
    fi
done

if [[ -f "$OUTPUT" && "${FORCE:-0}" != "1" ]]; then
    echo "Error: output file already exists: $OUTPUT"
    echo "  Use --force to overwrite."
    exit 1
fi

# --- Create working directory ---
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
ROOTFS_DIR="$WORK_DIR/rootfs"
mkdir -p "$ROOTFS_DIR"

echo "==> Downloading Alpine Linux ${ALPINE_FULL} minirootfs..."
TARBALL="$WORK_DIR/alpine-minirootfs.tar.gz"
curl -fSL --progress-bar -o "$TARBALL" "$TARBALL_URL"

echo "==> Extracting to $ROOTFS_DIR..."
tar xzf "$TARBALL" -C "$ROOTFS_DIR"

# --- Configure the rootfs for Firecracker boot ---

echo "==> Configuring init system (OpenRC)..."

# /etc/inittab — OpenRC-based init with serial console
cat > "$ROOTFS_DIR/etc/inittab" <<'INITTAB'
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default

# Serial console for Firecracker (console=ttyS0 in boot args)
ttyS0::respawn:/sbin/getty -L 0 ttyS0 vt100

::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
INITTAB

# /etc/fstab — mount proc, sys, dev at boot
cat > "$ROOTFS_DIR/etc/fstab" <<'FSTAB'
/dev/vda    /           ext4    rw,relatime     0 1
proc        /proc       proc    defaults        0 0
sysfs       /sys        sysfs   defaults        0 0
devtmpfs    /dev        devtmpfs defaults       0 0
devpts      /dev/pts    devpts  defaults        0 0
tmpfs       /tmp        tmpfs   defaults        0 0
tmpfs       /run        tmpfs   defaults        0 0
FSTAB

# /etc/hostname
echo "nexus-vm" > "$ROOTFS_DIR/etc/hostname"

# /etc/hosts
cat > "$ROOTFS_DIR/etc/hosts" <<'HOSTS'
127.0.0.1   localhost nexus-vm
::1         localhost nexus-vm
HOSTS

# /etc/resolv.conf — DNS (will be overwritten by networking step later)
cat > "$ROOTFS_DIR/etc/resolv.conf" <<'RESOLV'
nameserver 1.1.1.1
nameserver 8.8.8.8
RESOLV

# /etc/network/interfaces — loopback + eth0 via DHCP
mkdir -p "$ROOTFS_DIR/etc/network"
cat > "$ROOTFS_DIR/etc/network/interfaces" <<'IFACES'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
IFACES

# Enable essential OpenRC services via symlinks
# (Alpine minirootfs includes openrc but nothing is enabled by default)
mkdir -p "$ROOTFS_DIR/etc/runlevels/sysinit"
mkdir -p "$ROOTFS_DIR/etc/runlevels/boot"
mkdir -p "$ROOTFS_DIR/etc/runlevels/default"
mkdir -p "$ROOTFS_DIR/etc/runlevels/shutdown"

# sysinit level — bare minimum for hardware/device init
for svc in devfs dmesg mdev; do
    ln -sf "/etc/init.d/$svc" "$ROOTFS_DIR/etc/runlevels/sysinit/$svc" 2>/dev/null || true
done

# boot level — filesystem, hostname, networking prerequisites
for svc in hwclock modules sysctl hostname bootmisc syslog; do
    ln -sf "/etc/init.d/$svc" "$ROOTFS_DIR/etc/runlevels/boot/$svc" 2>/dev/null || true
done

# default level — networking and user services
for svc in networking; do
    ln -sf "/etc/init.d/$svc" "$ROOTFS_DIR/etc/runlevels/default/$svc" 2>/dev/null || true
done

# shutdown level
for svc in mount-ro killprocs savecache; do
    ln -sf "/etc/init.d/$svc" "$ROOTFS_DIR/etc/runlevels/shutdown/$svc" 2>/dev/null || true
done

# /etc/nexus/ — image metadata (read by guest-agent at boot, step 7)
mkdir -p "$ROOTFS_DIR/etc/nexus"
cat > "$ROOTFS_DIR/etc/nexus/image.yaml" <<'IMAGEMETA'
name: nexus/base-alpine
version: 0.1.0
access:
  terminal: vsock-pty
  mcp: vsock
IMAGEMETA

# Ensure /root exists with correct permissions
mkdir -p "$ROOTFS_DIR/root"
chmod 0700 "$ROOTFS_DIR/root"

# Create /usr/bin placeholder for guest-agent (installed in step 7)
mkdir -p "$ROOTFS_DIR/usr/bin"

echo "==> Packaging as ext4 image (${SIZE_MB}MB) via mke2fs -d..."
mkdir -p "$(dirname "$OUTPUT")"

# mke2fs -d creates an ext4 filesystem populated from a directory.
# No root privileges required.
#   -d <dir>    : populate from directory
#   -t ext4     : filesystem type
#   -L nexus-rootfs : volume label
#   -b 4096     : block size
# Size is specified in blocks (SIZE_MB * 1024 * 1024 / 4096 = SIZE_MB * 256)
BLOCK_COUNT=$(( SIZE_MB * 256 ))

# Remove existing output if --force
if [[ -f "$OUTPUT" ]]; then
    rm -f "$OUTPUT"
fi

mke2fs -q \
    -t ext4 \
    -d "$ROOTFS_DIR" \
    -L nexus-rootfs \
    -b 4096 \
    "$OUTPUT" \
    "${BLOCK_COUNT}"

# Report results
OUTPUT_SIZE=$(stat --format='%s' "$OUTPUT" 2>/dev/null || stat -f '%z' "$OUTPUT")
OUTPUT_SIZE_MB=$(( OUTPUT_SIZE / 1024 / 1024 ))

echo ""
echo "==> Alpine rootfs image created successfully"
echo "    Output:   $OUTPUT"
echo "    Size:     ${OUTPUT_SIZE_MB}MB (${SIZE_MB}MB allocated)"
echo "    Alpine:   ${ALPINE_FULL}"
echo "    Format:   ext4 (mke2fs -d, no root required)"
echo ""
echo "To import as a master image:"
echo "    nexusctl image import $(dirname "$OUTPUT") --name base-alpine"
