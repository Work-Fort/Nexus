// SPDX-License-Identifier: Apache-2.0

// Package containerd implements domain.Runtime using the containerd Go client.
package containerd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// Runtime implements domain.Runtime backed by containerd.
type Runtime struct {
	client    *client.Client
	namespace string
}

// New connects to containerd at the given socket path and returns a Runtime
// scoped to the given namespace.
func New(socketPath, namespace string) (*Runtime, error) {
	c, err := client.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd: %w", err)
	}
	return &Runtime{client: c, namespace: namespace}, nil
}

// Close closes the underlying containerd client connection.
func (r *Runtime) Close() error {
	return r.client.Close()
}

// nsCtx returns a context with the containerd namespace set.
func (r *Runtime) nsCtx(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, r.namespace)
}

// Create pulls the given image (if not already present) and creates a
// container with the specified runtime handler.
//
// We read the image config from the content store and build the OCI spec
// manually instead of using oci.WithImageConfig, which performs a client-side
// overlay mount to resolve supplemental groups from /etc/group inside the
// image. That mount requires CAP_SYS_ADMIN, preventing nexusd from running
// as an unprivileged systemd user service.
//
// Trade-off: named USER directives (e.g. "USER nginx") cannot be resolved
// to a UID without mounting the rootfs. We support numeric UIDs only.
// See README.md "Known Limitations" for details.
func (r *Runtime) Create(ctx context.Context, id, image, runtimeHandler string, opts ...domain.CreateOpt) error {
	ctx = r.nsCtx(ctx)

	img, err := r.client.Pull(ctx, image, client.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("pull image %s: %w", image, err)
	}

	imgSpec, err := img.Spec(ctx)
	if err != nil {
		return fmt.Errorf("read image config %s: %w", image, err)
	}
	cfg := imgSpec.Config

	specOpts := []oci.SpecOpts{oci.WithDefaultSpec()}

	args := append(cfg.Entrypoint, cfg.Cmd...)
	if len(args) > 0 {
		specOpts = append(specOpts, oci.WithProcessArgs(args...))
	}
	if len(cfg.Env) > 0 {
		specOpts = append(specOpts, oci.WithEnv(cfg.Env))
	}
	cwd := cfg.WorkingDir
	if cwd == "" {
		cwd = "/"
	}
	specOpts = append(specOpts, oci.WithProcessCwd(cwd))

	if cfg.User != "" {
		uid, gid, err := parseNumericUser(cfg.User)
		if err != nil {
			return fmt.Errorf("non-numeric USER %q in image %s (see README known limitations): %w", cfg.User, image, err)
		}
		specOpts = append(specOpts, oci.WithUIDGID(uid, gid))
	}

	var createCfg domain.CreateConfig
	for _, opt := range opts {
		opt(&createCfg)
	}
	if createCfg.NetNSPath != "" {
		specOpts = append(specOpts, oci.WithLinuxNamespace(specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: createCfg.NetNSPath,
		}))
	}

	_, err = r.client.NewContainer(ctx, id,
		client.WithImage(img),
		client.WithNewSnapshot(id+"-snap", img),
		client.WithRuntime(runtimeHandler, nil),
		client.WithNewSpec(specOpts...),
	)
	if err != nil {
		return fmt.Errorf("create container %s: %w", id, err)
	}
	return nil
}

// parseNumericUser parses "UID" or "UID:GID" strings into numeric values.
func parseNumericUser(user string) (uint32, uint32, error) {
	var uidStr, gidStr string
	if i := strings.Index(user, ":"); i >= 0 {
		uidStr, gidStr = user[:i], user[i+1:]
	} else {
		uidStr = user
		gidStr = "0"
	}

	uid, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q: %w", uidStr, err)
	}
	gid, err := strconv.ParseUint(gidStr, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q: %w", gidStr, err)
	}
	return uint32(uid), uint32(gid), nil
}

// Start creates and starts a task for the given container.
func (r *Runtime) Start(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.NewTask(ctx, cio.NullIO)
	if err != nil {
		return fmt.Errorf("create task %s: %w", id, err)
	}

	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("start task %s: %w", id, err)
	}
	return nil
}

// Stop kills the task (SIGTERM), waits up to 10 seconds for exit, then
// falls back to SIGKILL before deleting the task. If the process has
// already exited, Stop skips the kill and proceeds to delete the task.
func (r *Runtime) Stop(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil // no task means nothing to stop
		}
		return fmt.Errorf("get task %s: %w", id, err)
	}

	ch, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("wait task %s: %w", id, err)
	}

	if err := task.Kill(ctx, syscall.SIGTERM); err != nil {
		if !errdefs.IsNotFound(err) {
			return fmt.Errorf("kill task %s: %w", id, err)
		}
		// Process already exited; fall through to delete.
	} else {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			task.Kill(ctx, syscall.SIGKILL) //nolint:errcheck // best-effort force kill
			<-ch
		}
	}

	if _, err := task.Delete(ctx); err != nil {
		if errdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete task %s: %w", id, err)
	}
	return nil
}

// Delete removes the container and its associated snapshot.
func (r *Runtime) Delete(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	return container.Delete(ctx, client.WithSnapshotCleanup)
}

// Exec runs a command inside the running container's task and captures output.
func (r *Runtime) Exec(ctx context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get task %s: %w", id, err)
	}

	var stdout, stderr bytes.Buffer

	spec, err := container.Spec(ctx)
	if err != nil {
		return nil, fmt.Errorf("get spec %s: %w", id, err)
	}

	pspec := *spec.Process // struct copy to avoid mutating shared spec
	pspec.Args = cmd

	execID := fmt.Sprintf("%s-exec-%s", id, uuid.New().String()[:8])
	proc, err := task.Exec(ctx, execID, &pspec,
		cio.NewCreator(cio.WithFIFODir(os.TempDir()), cio.WithStreams(nil, &stdout, &stderr)),
	)
	if err != nil {
		return nil, fmt.Errorf("exec in %s: %w", id, err)
	}

	if err := proc.Start(ctx); err != nil {
		return nil, fmt.Errorf("start exec %s: %w", id, err)
	}

	ch, err := proc.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("wait exec %s: %w", id, err)
	}
	status := <-ch

	proc.Delete(ctx) //nolint:errcheck // best-effort cleanup

	return &domain.ExecResult{
		ExitCode: int(status.ExitCode()),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}
