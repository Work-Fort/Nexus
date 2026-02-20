use clap::Parser;
use nexus_lib::backend::btrfs::BtrfsBackend;
use nexus_lib::config::{self, Config};
use nexus_lib::pipeline::PipelineExecutor;
use nexus_lib::store::sqlite::SqliteStore;
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

    let workspaces_root = std::path::PathBuf::from(&config.storage.workspaces);

    let backend = match BtrfsBackend::new(workspaces_root.clone()) {
        Ok(backend) => {
            info!(workspaces = %workspaces_root.display(), "workspace backend initialized");
            backend
        }
        Err(e) => {
            error!(error = %e, "failed to initialize workspace backend");
            std::process::exit(1);
        }
    };

    let assets_dir = nexus_lib::config::default_assets_dir();
    let executor = PipelineExecutor::new();

    let state = Arc::new(api::AppState {
        store: Box::new(store),
        backend: Box::new(backend),
        workspaces_root,
        assets_dir,
        executor,
        firecracker: config.firecracker.clone(),
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
