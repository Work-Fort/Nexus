// SPDX-License-Identifier: Apache-2.0

// Package containerd implements domain.Runtime using the containerd Go client.
package containerd

import (
	"bytes"
	"context"
	"fmt"
	"syscall"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"

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
func (r *Runtime) Create(ctx context.Context, id, image, runtimeHandler string) error {
	ctx = r.nsCtx(ctx)

	img, err := r.client.Pull(ctx, image, client.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("pull image %s: %w", image, err)
	}

	_, err = r.client.NewContainer(ctx, id,
		client.WithImage(img),
		client.WithNewSnapshot(id+"-snap", img),
		client.WithRuntime(runtimeHandler, nil),
		client.WithNewSpec(oci.WithImageConfig(img)),
	)
	if err != nil {
		return fmt.Errorf("create container %s: %w", id, err)
	}
	return nil
}

// Start creates and starts a task for the given container.
func (r *Runtime) Start(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return fmt.Errorf("create task %s: %w", id, err)
	}

	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("start task %s: %w", id, err)
	}
	return nil
}

// Stop kills the task (SIGTERM), waits for it to exit, then deletes it.
func (r *Runtime) Stop(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return fmt.Errorf("get task %s: %w", id, err)
	}

	if err := task.Kill(ctx, syscall.SIGTERM); err != nil {
		return fmt.Errorf("kill task %s: %w", id, err)
	}

	ch, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("wait task %s: %w", id, err)
	}
	<-ch

	if _, err := task.Delete(ctx); err != nil {
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

	pspec := spec.Process
	pspec.Args = cmd

	execID := id + "-exec"
	proc, err := task.Exec(ctx, execID, pspec,
		cio.NewCreator(cio.WithStreams(nil, &stdout, &stderr)),
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
