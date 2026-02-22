// SPDX-License-Identifier: GPL-2.0-only
use crate::api::AppState;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

/// Poll interval for checking VM process status.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Spawn the process monitor as a background task.
///
/// This task runs until the provided shutdown signal completes.
/// It checks all running VMs' processes and transitions any that
/// have exited to the `crashed` state.
pub fn spawn(state: Arc<AppState>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut tick = interval(POLL_INTERVAL);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    check_processes(&state).await;
                }
                _ = shutdown.changed() => {
                    info!("process monitor shutting down");
                    break;
                }
            }
        }
    });
}

async fn check_processes(state: &AppState) {
    let mut processes = state.processes.lock().await;

    // Collect VM IDs whose processes have exited
    let mut exited = Vec::new();

    for (vm_id, tracked) in processes.iter_mut() {
        match tracked.child.try_wait() {
            Ok(Some(status)) => {
                // Process has exited
                let exit_code = status.code();
                warn!(
                    vm_id = %vm_id,
                    exit_code = ?exit_code,
                    "Firecracker process exited unexpectedly"
                );
                exited.push((*vm_id, exit_code));
            }
            Ok(None) => {
                // Process is still running — nothing to do
            }
            Err(e) => {
                warn!(vm_id = %vm_id, error = %e, "cannot check process status");
            }
        }
    }

    // Transition exited VMs to crashed and record boot stop
    for (vm_id, exit_code) in &exited {
        if let Some(tracked) = processes.remove(vm_id) {
            // Record boot stop with exit details
            let error_msg = exit_code.map(|c| format!("process exited with code {c}"));
            let _ = state.store.record_boot_stop(
                tracked.boot_id,
                *exit_code,
                error_msg.as_deref(),
            );
        }

        if let Err(e) = state.store.crash_vm(*vm_id) {
            warn!(vm_id = %vm_id, error = %e, "failed to transition VM to crashed");
        } else {
            info!(vm_id = %vm_id, "VM transitioned to crashed state");
        }

        // Close vsock connections (both control and MCP)
        state.vsock_manager.close_connection(*vm_id).await;
    }
}
