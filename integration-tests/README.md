# Nexus Integration Tests

Real end-to-end integration tests that verify Nexus works with actual external services.

## Overview

These tests:
- Download from real external services (GitHub, Alpine CDN, Firecracker releases)
- Verify full VM lifecycle (create → start → verify → stop → restart)
- Start from fresh, clean install (no cache, no database)
- Require: KVM + btrfs + network + systemd

## Running Tests

```bash
cd ~/Work/WorkFort/nexus
mise run integration-test
```

## Prerequisites

1. **KVM access**: `/dev/kvm` must be accessible
   ```bash
   ls -l /dev/kvm
   # Add user to kvm group if needed:
   sudo usermod -a -G kvm $USER
   ```

2. **btrfs filesystem**: Working directory must be on btrfs
   ```bash
   df -T .
   # Should show "btrfs" in Type column
   ```

3. **Network connectivity**: Tests download from:
   - GitHub (kernels, Firecracker releases)
   - Alpine CDN (rootfs images)

4. **systemd**: Required for daemon management
   ```bash
   systemctl --user --version
   ```

## Test Workflow

1. Clean environment (remove all Nexus state)
2. Verify prerequisites (KVM, btrfs, network, systemd)
3. Start daemon
4. Verify clean state (no cached binaries)
5. Download kernel, rootfs, Firecracker (real downloads)
6. Verify downloads present and executable
7. Create minimal Alpine 3.23.3 VM
8. Start VM → comprehensive verification:
   - PID alive in process table
   - Process is Firecracker
   - lsof shows PID owns UDS socket
   - UDS connection works
   - VM reaches "ready" state
   - vsock client verifies guest agent
9. Stop VM → verify cleanup:
   - PID no longer exists
   - PID null in database
10. Restart VM → verify new process:
    - New PID (different from previous)
    - New PID matches database
    - All verification checks pass

## Exit Codes

- `0`: Success - all tests passed
- `1`: Failure - test failed
- `2`: DNF (Did Not Finish) - prerequisites not met

## DNF Conditions

Tests exit with DNF (code 2) when:
- `/dev/kvm` not accessible
- Working directory not on btrfs
- Network connectivity check fails (GitHub unreachable)
- systemd not available

## CI Integration

Daily smoke test at 4:20 PM Mountain Time:
- Workflow: `.github/workflows/integration-test.yml.disabled`
- Requires: Self-hosted runner with KVM support
- See workflow file for setup instructions

## Timeouts

- VM boot: ~150ms (expected)
- Guest agent connection: 20 seconds (timeout)
- Downloads: 5 minutes per asset (timeout)

## Alpine Version

**CRITICAL**: Pre-alpha constraint - Alpine 3.23.3 ONLY
- Tests hardcode version `3.23.3`
- Do not use "latest" or version discovery
