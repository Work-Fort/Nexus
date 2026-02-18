use clap::{Parser, Subcommand};
use nexus_lib::client::NexusClient;
use nexus_lib::vm::{CreateVmParams, VmRole};
use std::path::PathBuf;
use std::process::ExitCode;

mod config;

// Exit codes per CLI spec
const EXIT_GENERAL_ERROR: u8 = 1;
const EXIT_DAEMON_UNREACHABLE: u8 = 3;
const EXIT_NOT_FOUND: u8 = 4;
const EXIT_CONFLICT: u8 = 5;

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
    /// Manage virtual machines
    Vm {
        #[command(subcommand)]
        action: VmAction,
    },
}

#[derive(Subcommand)]
enum VmAction {
    /// List all VMs
    List {
        /// Filter by role (work, portal, service)
        #[arg(long)]
        role: Option<String>,
        /// Filter by state (created, running, stopped, crashed, failed)
        #[arg(long)]
        state: Option<String>,
    },
    /// Create a new VM
    Create {
        /// VM name
        name: String,
        /// VM role: work, portal, service
        #[arg(long, default_value = "work")]
        role: String,
        /// vCPU count
        #[arg(long, default_value = "1")]
        vcpu: u32,
        /// Memory in MiB
        #[arg(long, default_value = "128")]
        mem: u32,
    },
    /// Show VM details
    Inspect {
        /// VM name or ID
        name: String,
    },
    /// Delete a VM
    Delete {
        /// VM name or ID
        name: String,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
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
        Commands::Vm { action } => cmd_vm(&daemon_addr, action).await,
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
            print_connect_error(daemon_addr);
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

async fn cmd_vm(daemon_addr: &str, action: VmAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        VmAction::List { role, state } => {
            match client.list_vms(role.as_deref(), state.as_deref()).await {
                Ok(vms) => {
                    if vms.is_empty() {
                        println!("No VMs found.");
                        return ExitCode::SUCCESS;
                    }
                    // Print table header
                    println!(
                        "{:<20} {:<10} {:<10} {:<6} {:<8} {:<6}",
                        "NAME", "ROLE", "STATE", "VCPU", "MEM", "CID"
                    );
                    for vm in &vms {
                        println!(
                            "{:<20} {:<10} {:<10} {:<6} {:<8} {:<6}",
                            vm.name, vm.role, vm.state, vm.vcpu_count,
                            format!("{}M", vm.mem_size_mib), vm.cid,
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        VmAction::Create { name, role, vcpu, mem } => {
            let role: VmRole = match role.parse() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };
            let params = CreateVmParams {
                name: name.clone(),
                role,
                vcpu_count: vcpu,
                mem_size_mib: mem,
            };
            match client.create_vm(&params).await {
                Ok(vm) => {
                    println!("Created VM \"{}\" (state: {}, CID: {})", vm.name, vm.state, vm.cid);
                    println!("\n  Inspect it: nexusctl vm inspect {}", vm.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot create VM \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_CONFLICT)
                }
            }
        }
        VmAction::Inspect { name } => {
            match client.get_vm(&name).await {
                Ok(Some(vm)) => {
                    println!("Name:       {}", vm.name);
                    println!("ID:         {}", vm.id);
                    println!("Role:       {}", vm.role);
                    println!("State:      {}", vm.state);
                    println!("CID:        {}", vm.cid);
                    println!("vCPUs:      {}", vm.vcpu_count);
                    println!("Memory:     {} MiB", vm.mem_size_mib);
                    println!("Created:    {}", format_timestamp(vm.created_at));
                    if let Some(ts) = vm.started_at {
                        println!("Started:    {}", format_timestamp(ts));
                    }
                    if let Some(ts) = vm.stopped_at {
                        println!("Stopped:    {}", format_timestamp(ts));
                    }
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: VM \"{}\" not found", name);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        VmAction::Delete { name, yes } => {
            if !yes {
                eprintln!(
                    "Error: refusing to delete VM without confirmation\n  \
                     Run with --yes to skip confirmation: nexusctl vm delete {} --yes",
                    name
                );
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
            match client.delete_vm(&name).await {
                Ok(true) => {
                    println!("Deleted VM \"{}\"", name);
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: VM \"{}\" not found", name);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot delete VM \"{}\"\n  {e}", name);
                    ExitCode::from(EXIT_CONFLICT)
                }
            }
        }
    }
}

fn print_connect_error(daemon_addr: &str) {
    eprintln!(
        "Error: cannot connect to Nexus daemon at {}\n  \
         The daemon does not appear to be running.\n\n  \
         Start it: systemctl --user start nexus.service",
        daemon_addr
    );
}

fn format_timestamp(epoch_secs: i64) -> String {
    chrono::DateTime::from_timestamp(epoch_secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| epoch_secs.to_string())
}
