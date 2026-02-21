// SPDX-License-Identifier: GPL-2.0-only
use clap::Parser;
use nexus_lib::backend::btrfs::BtrfsBackend;
use nexus_lib::config::{self, Config};
use nexus_lib::pipeline::PipelineExecutor;
use nexus_lib::store::sqlite::SqliteStore;
use nexus_lib::vsock_manager::VsockManager;
use tracing::{error, info};
use std::sync::Arc;

mod api;
mod logging;
mod monitor;
mod server;

#[derive(Parser)]
#[command(name = "nexusd", about = "WorkFort Nexus daemon")]
struct Cli {
    /// Path to configuration file
    /// [default: $XDG_CONFIG_HOME/nexus/nexus.yaml]
    #[arg(long)]
    config: Option<String>,

    /// Path to database file
    /// [default: $XDG_STATE_HOME/nexus/nexus.db]
    #[arg(long)]
    db: Option<String>,
}

/// Recover from stale VM state after daemon restart.
/// VMs marked as `running` from a previous daemon instance have no
/// managed Firecracker process — transition them to `crashed`.
fn recover_stale_vms(store: &dyn nexus_lib::store::traits::StateStore) {
    match store.list_running_vms() {
        Ok(vms) if vms.is_empty() => {}
        Ok(vms) => {
            for vm in &vms {
                tracing::warn!(
                    vm_name = %vm.name,
                    vm_id = %vm.id,
                    "recovering stale running VM from previous daemon instance"
                );
                if let Err(e) = store.crash_vm(vm.id) {
                    tracing::error!(
                        vm_name = %vm.name,
                        error = %e,
                        "failed to recover stale VM"
                    );
                }
            }
            tracing::info!(count = vms.len(), "recovered stale VMs");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to query running VMs during recovery");
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    logging::init();

    let config_path = cli
        .config
        .map(std::path::PathBuf::from)
        .unwrap_or_else(config::default_config_path);

    let config = match Config::load(&config_path) {
        Ok(config) => {
            info!(config_path = %config_path.display(), "loaded configuration");
            config
        }
        Err(e) if e.is_not_found() => {
            info!("no config file found, using defaults");
            Config::default()
        }
        Err(e) => {
            error!(error = %e, path = %config_path.display(), "invalid configuration file");
            std::process::exit(1);
        }
    };

    // Initialize SQLite state store
    let db_path = cli
        .db
        .map(std::path::PathBuf::from)
        .unwrap_or_else(config::default_db_path);

    let store = match SqliteStore::open_and_init(&db_path) {
        Ok(store) => {
            info!(db_path = %db_path.display(), "database initialized");
            store
        }
        Err(e) => {
            error!(error = %e, db_path = %db_path.display(), "failed to initialize database");
            std::process::exit(1);
        }
    };

    // Recover stale VMs from previous daemon instance
    recover_stale_vms(&store);

    let drives_root = std::path::PathBuf::from(&config.storage.drives);

    let backend = match BtrfsBackend::new(drives_root.clone()) {
        Ok(backend) => {
            info!(drives = %drives_root.display(), "drive backend initialized");
            backend
        }
        Err(e) => {
            error!(error = %e, "failed to initialize drive backend");
            std::process::exit(1);
        }
    };

    let assets_dir = nexus_lib::config::default_assets_dir();
    let executor = PipelineExecutor::new();

    // Wrap store in Arc for sharing between VsockManager and AppState
    let store_box: Box<dyn nexus_lib::store::traits::StateStore + Send + Sync> = Box::new(store);
    let store_arc: Arc<dyn nexus_lib::store::traits::StateStore + Send + Sync> = Arc::from(store_box);

    // Initialize VsockManager and start monitor task
    let vsock_manager = Arc::new(VsockManager::new(store_arc.clone()));
    vsock_manager.clone().start_monitor_task();

    let state = Arc::new(api::AppState {
        store: store_arc,
        backend: Box::new(backend),
        drives_root,
        assets_dir,
        executor,
        firecracker: config.firecracker.clone(),
        vsock_manager,
        processes: tokio::sync::Mutex::new(std::collections::HashMap::new()),
    });

    // Start process monitor
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    monitor::spawn(state.clone(), shutdown_rx);

    info!("nexusd starting");

    if let Err(e) = server::run(&config, state).await {
        error!(error = %e, "daemon failed");
        std::process::exit(1);
    }

    // Signal the monitor to stop
    let _ = shutdown_tx.send(true);
}
