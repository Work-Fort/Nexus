// SPDX-License-Identifier: Apache-2.0

// Package containerd implements domain.Runtime using the containerd Go client.
package containerd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/Work-Fort/Nexus/pkg/nxid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// Runtime implements domain.Runtime backed by containerd.
type Runtime struct {
	client      *client.Client
	namespace   string
	snapshotter string
	quotaHelper string // path to nexus-quota binary, empty to skip
}

// New connects to containerd at the given socket path and returns a Runtime
// scoped to the given namespace.
func New(socketPath, namespace, snapshotter, quotaHelper string) (*Runtime, error) {
	c, err := client.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd: %w", err)
	}
	if snapshotter == "" {
		snapshotter = "overlayfs"
	}
	return &Runtime{
		client:      c,
		namespace:   namespace,
		snapshotter: snapshotter,
		quotaHelper: quotaHelper,
	}, nil
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
// image. That mount requires CAP_SYS_ADMIN, preventing nexus from running
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

	if len(createCfg.Mounts) > 0 {
		var ociMounts []specs.Mount
		for _, m := range createCfg.Mounts {
			ociMounts = append(ociMounts, specs.Mount{
				Destination: m.ContainerPath,
				Type:        "bind",
				Source:      m.HostPath,
				Options:     []string{"rbind", "rw"},
			})
		}
		specOpts = append(specOpts, oci.WithMounts(ociMounts))
	}

	if len(createCfg.Devices) > 0 {
		specOpts = append(specOpts, withDevices(createCfg.Devices))
	}

	if createCfg.ResolvConfPath != "" {
		specOpts = append(specOpts, oci.WithMounts([]specs.Mount{{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      createCfg.ResolvConfPath,
			Options:     []string{"rbind", "ro"},
		}}))
	}

	_, err = r.client.NewContainer(ctx, id,
		client.WithImage(img),
		client.WithSnapshotter(r.snapshotter),
		client.WithNewSnapshot(id+"-snap", img),
		client.WithRuntime(runtimeHandler, nil),
		client.WithNewSpec(specOpts...),
	)
	if err != nil {
		return fmt.Errorf("create container %s: %w", id, err)
	}

	if createCfg.RootSize > 0 {
		if err := r.setSnapshotQuota(ctx, id+"-snap", createCfg.RootSize); err != nil {
			// Clean up the container we just created.
			container, _ := r.client.LoadContainer(ctx, id)
			if container != nil {
				container.Delete(ctx, client.WithSnapshotCleanup) //nolint:errcheck
			}
			return fmt.Errorf("set root size quota: %w", err)
		}
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

// withDevices returns an OCI spec option that adds device nodes and cgroup allow rules.
func withDevices(devices []domain.DeviceInfo) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		if s.Linux.Resources == nil {
			s.Linux.Resources = &specs.LinuxResources{}
		}
		for _, dev := range devices {
			fi, err := os.Stat(dev.HostPath)
			if err != nil {
				return fmt.Errorf("stat device %s: %w", dev.HostPath, err)
			}
			stat, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot get device info for %s", dev.HostPath)
			}

			devType := "c"
			if fi.Mode()&os.ModeDevice != 0 && fi.Mode()&os.ModeCharDevice == 0 {
				devType = "b"
			}
			major := int64(unix.Major(stat.Rdev))
			minor := int64(unix.Minor(stat.Rdev))

			gid := dev.GID
			s.Linux.Devices = append(s.Linux.Devices, specs.LinuxDevice{
				Path:  dev.ContainerPath,
				Type:  devType,
				Major: major,
				Minor: minor,
				GID:   &gid,
			})

			s.Linux.Resources.Devices = append(s.Linux.Resources.Devices, specs.LinuxDeviceCgroup{
				Allow:  true,
				Type:   devType,
				Major:  &major,
				Minor:  &minor,
				Access: dev.Permissions,
			})
		}
		return nil
	}
}

// SetSnapshotQuota sets a btrfs qgroup limit on the given snapshot.
// Exposed for use by the expand endpoint.
func (r *Runtime) SetSnapshotQuota(ctx context.Context, snapName string, sizeBytes int64) error {
	return r.setSnapshotQuota(r.nsCtx(ctx), snapName, sizeBytes)
}

// setSnapshotQuota sets a btrfs qgroup limit on the snapshot's subvolume.
func (r *Runtime) setSnapshotQuota(ctx context.Context, snapName string, sizeBytes int64) error {
	if r.quotaHelper == "" {
		return fmt.Errorf("quota helper not configured")
	}

	snapshotter := r.client.SnapshotService(r.snapshotter)
	mounts, err := snapshotter.Mounts(ctx, snapName)
	if err != nil {
		return fmt.Errorf("get snapshot mounts %s: %w", snapName, err)
	}
	if len(mounts) == 0 {
		return fmt.Errorf("no mounts for snapshot %s", snapName)
	}

	// For btrfs snapshotter, the mount source is the subvolume path.
	subvolPath := mounts[0].Source

	cmd := exec.CommandContext(ctx, r.quotaHelper, "set-limit", subvolPath, strconv.FormatInt(sizeBytes, 10))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s set-limit %s %d: %s: %w", r.quotaHelper, subvolPath, sizeBytes, string(out), err)
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

	execID := fmt.Sprintf("%s-exec-%s", id, nxid.New())
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

// ExportImage writes the OCI image as a tar stream to w.
func (r *Runtime) ExportImage(ctx context.Context, imageRef string, w io.Writer) error {
	ctx = r.nsCtx(ctx)

	img, err := r.client.GetImage(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("get image %s: %w", imageRef, err)
	}

	return r.client.Export(ctx, w, archive.WithImage(r.client.ImageService(), img.Name()))
}

// ImportImage reads an OCI image tar stream from reader and returns the image reference.
func (r *Runtime) ImportImage(ctx context.Context, reader io.Reader) (string, error) {
	ctx = r.nsCtx(ctx)

	imgs, err := r.client.Import(ctx, reader)
	if err != nil {
		return "", fmt.Errorf("import image: %w", err)
	}
	if len(imgs) == 0 {
		return "", fmt.Errorf("import returned no images")
	}
	return imgs[0].Name, nil
}

// WatchExits subscribes to task exit events in this runtime's namespace and
// calls onExit for each container init process that exits. Blocks until ctx
// is canceled. Exec process exits (e.ID != e.ContainerID) are filtered out.
func (r *Runtime) WatchExits(ctx context.Context, onExit func(containerID string, exitCode uint32)) error {
	ctx = r.nsCtx(ctx)
	ch, errs := r.client.Subscribe(ctx, `topic=="/tasks/exit"`)

	for {
		select {
		case env := <-ch:
			if env == nil {
				return nil
			}
			v, err := typeurl.UnmarshalAny(env.Event)
			if err != nil {
				continue
			}
			e, ok := v.(*apievents.TaskExit)
			if !ok {
				continue
			}
			// Only handle init process exits, not exec process exits.
			if e.ID != e.ContainerID {
				continue
			}
			onExit(e.ContainerID, e.ExitStatus)

		case err := <-errs:
			if err == nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("event stream: %w", err)
		}
	}
}
