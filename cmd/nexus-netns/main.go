// SPDX-License-Identifier: Apache-2.0

// nexus-netns is a minimal helper that creates or deletes persistent network
// namespaces. It requires CAP_SYS_ADMIN (via setcap) so that the main nexusd
// daemon can remain unprivileged.
//
// Usage:
//
//	nexus-netns create <path>   — create a netns and bind-mount it at <path>
//	nexus-netns delete <path>   — unmount and remove the netns at <path>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: nexus-netns <create|delete> <path>\n")
		os.Exit(1)
	}

	cmd, nsPath := os.Args[1], os.Args[2]

	switch cmd {
	case "create":
		if err := createNetNS(nsPath); err != nil {
			fmt.Fprintf(os.Stderr, "create: %v\n", err)
			os.Exit(1)
		}
	case "delete":
		if err := deleteNetNS(nsPath); err != nil {
			fmt.Fprintf(os.Stderr, "delete: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func createNetNS(nsPath string) error {
	if err := os.MkdirAll(filepath.Dir(nsPath), 0755); err != nil {
		return fmt.Errorf("create netns dir: %w", err)
	}

	f, err := os.Create(nsPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	f.Close()

	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread — the thread exits with the goroutine,
		// keeping the caller's namespace untouched.

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("unshare: %w", err)
			return
		}

		src := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		if err := unix.Mount(src, nsPath, "none", unix.MS_BIND, ""); err != nil {
			errCh <- fmt.Errorf("bind mount: %w", err)
			return
		}

		errCh <- nil
	}()

	if err := <-errCh; err != nil {
		os.Remove(nsPath)
		return err
	}
	return nil
}

func deleteNetNS(nsPath string) error {
	if err := unix.Unmount(nsPath, unix.MNT_DETACH); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("unmount: %w", err)
		}
	}
	if err := os.Remove(nsPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}
