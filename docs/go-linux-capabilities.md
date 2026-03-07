# Go and Linux Capabilities

Reference for working with Linux capabilities in Go programs,
especially when spawning subprocesses that need elevated privileges.

## The Problem: Ambient Caps and Go's Thread Model

Linux capabilities are **per-thread**, not per-process. Go's goroutine
scheduler freely moves goroutines between OS threads. This creates a
fundamental mismatch: if you raise ambient capabilities on one thread,
a goroutine may later run on a different thread that lacks them.

**Symptoms:**
- Subprocess calls (`exec.Command`) intermittently fail with
  `Operation not permitted`
- Tests pass when run individually but fail when run together
- First test passes, subsequent tests fail (different goroutine,
  different thread)

## Capability Inheritance for Subprocesses

File capabilities (`setcap`) on a binary set the **permitted** and
**effective** sets at exec time. But these don't automatically pass
to child processes. To pass capabilities to spawned subprocesses:

1. **Inheritable set** — must include the capability (`capset`)
2. **Ambient set** — must be raised (`prctl PR_CAP_AMBIENT_RAISE`)
3. Child process inherits ambient caps at `fork+exec`

Without ambient caps, `exec.Command("btrfs", "send", ...)` runs the
`btrfs` binary without any capabilities, even if the parent process
has them.

## The Fix: Lock Thread + Raise Ambient Per-Goroutine

Every goroutine that needs to spawn privileged subprocesses must:

```go
runtime.LockOSThread()  // pin goroutine to this OS thread

// Raise each needed cap as ambient on THIS thread
for _, cap := range []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_FOWNER} {
    raiseAmbientCap(cap)
}

// Now exec.Command will inherit ambient caps
cmd := exec.Command("btrfs", "send", path)
cmd.Run()  // child inherits CAP_SYS_ADMIN + CAP_FOWNER
```

### Common Mistake: sync.Once

**Do not** use `sync.Once` to raise ambient caps once at startup.
The `Once` callback runs on one thread; subsequent goroutines run on
different threads without ambient caps.

```go
// WRONG — only sets caps on one thread
var once sync.Once
func ensureCaps() {
    once.Do(func() {
        runtime.LockOSThread()
        raiseAmbientCap(unix.CAP_SYS_ADMIN)
    })
}
```

### Correct Pattern for Tests

```go
func requireCaps(t *testing.T) {
    t.Helper()
    runtime.LockOSThread()
    for _, cap := range []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_FOWNER} {
        if err := raiseAmbientCap(cap); err != nil {
            t.Skipf("caps not available: %v", err)
        }
    }
}
```

Each test calls `requireCaps(t)` independently. This is safe because:
- `capset` and `prctl` are idempotent
- Each goroutine gets its own locked thread with ambient caps
- Go reclaims threads when goroutines exit

### Correct Pattern for Daemons/Helpers

For long-running binaries (like `nexus-btrfs`), raise caps once on
the main goroutine before exec-ing:

```go
func main() {
    runtime.LockOSThread()
    raiseAmbientCap(unix.CAP_SYS_ADMIN)
    raiseAmbientCap(unix.CAP_FOWNER)
    unix.Exec(btrfsPath, argv, os.Environ())  // replaces process
}
```

This works because `main()` is the only goroutine and `unix.Exec`
replaces the entire process.

## raiseAmbientCap Implementation

```go
func raiseAmbientCap(cap uintptr) error {
    var hdr unix.CapUserHeader
    hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
    var data [2]unix.CapUserData
    if err := unix.Capget(&hdr, &data[0]); err != nil {
        return fmt.Errorf("capget: %w", err)
    }

    word := cap / 32
    bit := uint32(1 << (cap % 32))

    if data[word].Permitted&bit == 0 {
        return fmt.Errorf("CAP %d not in permitted set", cap)
    }

    data[word].Inheritable |= bit
    if err := unix.Capset(&hdr, &data[0]); err != nil {
        return fmt.Errorf("capset: %w", err)
    }

    return unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, cap, 0, 0)
}
```

## Specific Capabilities We Use

| Capability | Why | Used By |
|---|---|---|
| `CAP_SYS_ADMIN` | btrfs ioctls (send, receive, quota), network namespaces | nexus-btrfs, nexus-netns, nexus-quota |
| `CAP_FOWNER` | btrfs-progs opens mount point with `O_NOATIME` (requires ownership or `CAP_FOWNER`) | nexus-btrfs |
| `CAP_NET_ADMIN` | CNI plugin operations | nexus-cni-exec |
| `CAP_NET_BIND_SERVICE` | Bind DNS port 53 | nexus-dns |

## dev-setcap-loop Scripts

Two setcap scripts auto-apply file caps during development:

- **`scripts/dev-setcap-loop.sh`** — sets caps on all helper binaries in `build/`
- **`pkg/btrfs/scripts/dev-setcap-loop.sh`** — sets caps on the btrfs test binary

Run with `sudo` in a separate terminal. They re-apply caps every 2
seconds to pick up rebuilds.

## Where This Applies in the Codebase

- `cmd/nexus-btrfs/main.go` — helper binary, raises ambient caps before exec
- `cmd/nexus-cni-exec/main.go` — same pattern for CNI
- `pkg/btrfs/e2e_test.go` — `requireSendReceiveCap` raises per-thread ambient caps
- `internal/infra/storage/btrfs.go` — uses helper binary for send/receive, ioctl for setReadOnly
