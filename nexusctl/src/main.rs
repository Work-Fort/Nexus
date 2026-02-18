use clap::{Parser, Subcommand};
use nexus_lib::client::NexusClient;
use std::path::PathBuf;
use std::process::ExitCode;

mod config;

// Exit codes per CLI spec
const EXIT_GENERAL_ERROR: u8 = 1;
const EXIT_DAEMON_UNREACHABLE: u8 = 3;

#[derive(Parser)]
#[command(
    name = "nexusctl",
    about = "WorkFort Nexus CLI (alias: nxc)",
    version
)]
struct Cli {
    /// Path to configuration file
    /// [default: $XDG_CONFIG_HOME/nexusctl/config.yaml]
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Daemon address (host:port)
    #[arg(long, global = true)]
    daemon: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show daemon status
    Status,
    /// Print version information
    Version,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let config_path = cli.config.unwrap_or_else(config::default_config_path);
    let cfg = config::load(&config_path);
    let daemon_addr = cli.daemon.unwrap_or(cfg.daemon);

    match cli.command {
        Commands::Status => cmd_status(&daemon_addr).await,
        Commands::Version => cmd_version(&daemon_addr).await,
    }
}

async fn cmd_status(daemon_addr: &str) -> ExitCode {
    let client = NexusClient::new(daemon_addr);
    match client.health().await {
        Ok(resp) => {
            println!("Daemon: {} ({})", resp.status, daemon_addr);
            if let Some(db) = resp.database {
                println!("Database: {}", db.path);
                println!("  Tables: {}", db.table_count);
                if let Some(size) = db.size_bytes {
                    println!("  Size:   {} bytes", size);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) if e.is_connect() => {
            eprintln!(
                "Error: cannot connect to Nexus daemon at {}\n  \
                 The daemon does not appear to be running.\n\n  \
                 Start it: systemctl --user start nexus.service",
                daemon_addr
            );
            ExitCode::from(EXIT_DAEMON_UNREACHABLE)
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(EXIT_GENERAL_ERROR)
        }
    }
}

async fn cmd_version(daemon_addr: &str) -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");
    println!("nexusctl {version}");

    let client = NexusClient::new(daemon_addr);
    match client.health().await {
        Ok(_) => {
            println!("nexusd   reachable at {daemon_addr}");
        }
        Err(_) => {
            println!("nexusd   not reachable at {daemon_addr}");
        }
    }
    ExitCode::SUCCESS
}
