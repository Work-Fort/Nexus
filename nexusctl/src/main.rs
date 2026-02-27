// SPDX-License-Identifier: GPL-2.0-only
use clap::{Parser, Subcommand};
use nexus_lib::client::NexusClient;
use nexus_lib::drive::{CreateDriveParams, ImportImageParams};
use nexus_lib::template::CreateTemplateParams;
use nexus_lib::vm::{CreateVmParams, VmRole};
use serde_json::json;
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
    /// Manage master images
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },
    /// Manage drives

    Drive {
        #[command(subcommand)]
        action: DriveAction,
    },
    /// Manage kernels
    Kernel {
        #[command(subcommand)]
        action: KernelAction,
    },
    /// Manage rootfs images
    Rootfs {
        #[command(subcommand)]
        action: RootfsAction,
    },
    /// Manage Firecracker binaries
    Firecracker {
        #[command(subcommand)]
        action: FirecrackerAction,
    },
    /// Manage templates
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },
    /// Manage builds
    Build {
        #[command(subcommand)]
        action: BuildAction,
    },
    /// MCP stdio to HTTP bridge (for Claude Desktop integration)
    McpBridge,
    /// Configure host firewall for VM networking (requires sudo)
    SetupFirewall,
    /// Manage configuration settings
    #[command(subcommand)]
    Config(ConfigCommands),
    /// Administrative / debug commands
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Get a configuration setting
    Get {
        /// Setting key (e.g., bridge-name, default-kernel-version)
        key: String,
    },
    /// Set a configuration setting
    Set {
        /// Setting key (e.g., bridge-name, dns-servers, service-port)
        key: String,
        /// Setting value(s). Most settings take one value.
        /// service-port takes: <name> <port>
        #[arg(required = true, num_args = 1..)]
        value: Vec<String>,
    },
    /// List all configuration settings
    List,
}

#[derive(Subcommand)]
enum AdminAction {
    /// Clean up all nexus network state (taps, bridge, nftables)
    CleanupNetwork,
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
    /// Start a VM
    Start {
        /// VM name or ID
        name: String,
    },
    /// Stop a running VM
    Stop {
        /// VM name or ID
        name: String,
        /// Force stop (SIGKILL instead of SIGTERM)
        #[arg(long)]
        force: bool,
    },
    /// View VM console logs
    Logs {
        /// VM name or ID
        name: String,
        /// Number of lines to show from the end
        #[arg(long, default_value = "100")]
        tail: usize,
    },
    /// View VM state transition history
    History {
        /// VM name or ID
        name: String,
    },
    /// Create VM from rootfs (downloads, builds, creates drive, attaches)
    FromRootfs {
        /// Distribution name (e.g., alpine)
        distro: String,
        /// Distribution version (e.g., 3.21)
        version: String,
        /// VM name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// VM role: work, portal, service
        #[arg(long, default_value = "work")]
        role: String,
        /// vCPU count
        #[arg(long, default_value = "1")]
        vcpu: u32,
        /// Memory in MiB
        #[arg(long, default_value = "128")]
        mem: u32,
        /// File overlay: path=content (can be repeated)
        #[arg(long = "overlay", value_name = "PATH=CONTENT")]
        overlays: Vec<String>,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Create VM from template (builds, creates drive, attaches)
    FromTemplate {
        /// Template name
        template: String,
        /// VM name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// VM role: work, portal, service
        #[arg(long, default_value = "work")]
        role: String,
        /// vCPU count
        #[arg(long, default_value = "1")]
        vcpu: u32,
        /// Memory in MiB
        #[arg(long, default_value = "128")]
        mem: u32,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Create VM from image (creates drive, attaches)
    FromImage {
        /// Image name or ID
        image: String,
        /// VM name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// VM role: work, portal, service
        #[arg(long, default_value = "work")]
        role: String,
        /// vCPU count
        #[arg(long, default_value = "1")]
        vcpu: u32,
        /// Memory in MiB
        #[arg(long, default_value = "128")]
        mem: u32,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },
    /// Add a provision file to inject into VM on start
    AddProvisionFile {
        /// VM name or ID
        vm: String,
        /// Path inside the guest where the file will be written
        #[arg(long)]
        guest_path: String,
        /// Host file path to read at provision time
        #[arg(long, conflicts_with = "content")]
        host_path: Option<String>,
        /// Inline content to write
        #[arg(long, conflicts_with = "host_path")]
        content: Option<String>,
        /// Encoding: text or base64 (default: text, auto-set to base64 for --host-path of binary files)
        #[arg(long, default_value = "text")]
        encoding: String,
        /// Unix file permissions (e.g., 0755)
        #[arg(long)]
        mode: Option<String>,
    },
    /// List provision files for a VM
    ProvisionFiles {
        /// VM name or ID
        vm: String,
    },
    /// Remove a provision file from a VM
    RemoveProvisionFile {
        /// VM name or ID
        vm: String,
        /// Guest path to remove
        #[arg(long)]
        guest_path: String,
    },
}

#[derive(Subcommand)]
enum ImageAction {
    /// List all master images
    List,
    /// Import a directory as a master image
    Import {
        /// Path to directory to import
        path: String,
        /// Name for the image
        #[arg(long)]
        name: String,
    },
    /// Show image details
    Inspect {
        /// Image name or ID
        name: String,
    },
    /// Delete a master image
    Delete {
        /// Image name or ID
        name: String,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },

    /// Create image from rootfs (downloads, builds)
    FromRootfs {
        /// Distribution name (e.g., alpine)
        distro: String,
        /// Distribution version (e.g., 3.21)
        version: String,
        /// Image name (derived from distro-version if omitted)
        #[arg(long)]
        name: Option<String>,
        /// File overlay: path=content (can be repeated)
        #[arg(long = "overlay", value_name = "PATH=CONTENT")]
        overlays: Vec<String>,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Create image from template (builds)
    FromTemplate {
        /// Template name
        template: String,
        /// Image name (derived from template if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum DriveAction {
    /// List all drives
    List {
        /// Filter by base image name
        #[arg(long)]
        base: Option<String>,
    },
    /// Create a drive from a master image
    Create {
        /// Drive name
        #[arg(long)]
        name: Option<String>,
        /// Base image name
        #[arg(long)]
        base: String,
        /// Drive size (e.g., "256M", "1G"). Defaults to master image size.
        #[arg(long)]
        size: Option<String>,
    },
    /// Show drive details
    Inspect {
        /// Drive name or ID
        name: String,
    },
    /// Delete a drive
    Delete {
        /// Drive name or ID
        name: String,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// Attach a drive to a VM
    Attach {
        /// Drive name or ID
        name: String,
        /// VM name or ID to attach to
        #[arg(long)]
        vm: String,
        /// Mount as root device
        #[arg(long, default_value = "true", default_missing_value = "true", num_args = 0..=1, require_equals = true)]
        root: bool,
    },
    /// Detach a drive from its VM
    Detach {
        /// Drive name or ID
        name: String,
    },

    /// Create drive from rootfs (downloads, builds, creates drive)
    FromRootfs {
        /// Distribution name (e.g., alpine)
        distro: String,
        /// Distribution version (e.g., 3.21)
        version: String,
        /// Drive name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// File overlay: path=content (can be repeated)
        #[arg(long = "overlay", value_name = "PATH=CONTENT")]
        overlays: Vec<String>,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Create drive from template (builds, creates drive)
    FromTemplate {
        /// Template name
        template: String,
        /// Drive name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Create drive from image
    FromImage {
        /// Image name or ID
        image: String,
        /// Drive name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum KernelAction {
    /// List available kernel versions from anvil
    List,
    /// Download a specific kernel version
    Download { version: String },
    /// List downloaded kernels
    Installed,
    /// Remove a downloaded kernel
    Remove { version: String },
    /// Verify a downloaded kernel's integrity (re-hash file on disk, compare to DB)
    Verify { version: String },
}

#[derive(Subcommand)]
enum RootfsAction {
    /// List available rootfs versions for a distro
    List { distro: String },
    /// Download a rootfs image
    Download { distro: String, version: String },
    /// List downloaded rootfs images
    Installed,
    /// Remove a downloaded rootfs image
    Remove { distro: String, version: String },
}

#[derive(Subcommand)]
enum FirecrackerAction {
    /// List available Firecracker versions
    List,
    /// Download a Firecracker binary
    Download { version: String },
    /// List downloaded Firecracker binaries
    Installed,
    /// Remove a downloaded Firecracker binary
    Remove { version: String },
}

#[derive(Subcommand)]
enum TemplateAction {
    /// List all templates
    List,
    /// Create a new template
    Create {
        /// Template name
        #[arg(long)]
        name: String,
        /// Source type (rootfs)
        #[arg(long, default_value = "rootfs")]
        source_type: String,
        /// Source identifier (URL or path to rootfs tarball)
        #[arg(long)]
        source: String,
        /// File overlay: path=content (can be repeated)
        #[arg(long = "overlay", value_name = "PATH=CONTENT")]
        overlays: Vec<String>,
    },
    /// Show template details
    Inspect {
        /// Template name or ID
        name: String,
    },
    /// Delete a template
    Delete {
        /// Template name or ID
        name: String,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum BuildAction {
    /// Trigger a build from a template
    Trigger {
        /// Template name or ID
        template: String,
    },
    /// List all builds
    List {
        /// Filter by template name
        #[arg(long)]
        template: Option<String>,
    },
    /// Show build details
    Inspect {
        /// Build ID
        id: String,
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
        Commands::Image { action } => cmd_image(&daemon_addr, action).await,
        Commands::Drive { action } => cmd_drive(&daemon_addr, action).await,
        Commands::Kernel { action } => cmd_kernel(&daemon_addr, action).await,
        Commands::Rootfs { action } => cmd_rootfs(&daemon_addr, action).await,
        Commands::Firecracker { action } => cmd_firecracker(&daemon_addr, action).await,
        Commands::Template { action } => cmd_template(&daemon_addr, action).await,
        Commands::Build { action } => cmd_build(&daemon_addr, action).await,
        Commands::McpBridge => cmd_mcp_bridge(&daemon_addr).await,
        Commands::SetupFirewall => cmd_setup_firewall().await,
        Commands::Config(cmd) => cmd_config(&daemon_addr, cmd).await,
        Commands::Admin { action } => cmd_admin(&daemon_addr, action).await,
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
                        "{:<13} {:<20} {:<10} {:<10} {:<15} {:<6} {:<8} {:<6}",
                        "ID", "NAME", "ROLE", "STATE", "NETWORK", "VCPU", "MEM", "CID"
                    );
                    for vm in &vms {
                        // Fetch network info for each VM
                        let network_info = match client.vm_inspect(&vm.id.encode()).await {
                            Ok(detail) => {
                                if let Some(network) = detail.network {
                                    network.ip_address
                                } else {
                                    "-".to_string()
                                }
                            }
                            Err(_) => "-".to_string(),
                        };
                        println!(
                            "{:<13} {:<20} {:<10} {:<10} {:<15} {:<6} {:<8} {:<6}",
                            vm.id, vm.name, vm.role, vm.state, network_info, vm.vcpu_count,
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
            match client.vm_inspect(&name).await {
                Ok(detail) => {
                    let vm = &detail.vm;
                    println!("Name:       {}", vm.name);
                    println!("ID:         {}", vm.id);
                    println!("Role:       {}", vm.role);
                    println!("State:      {}", vm.state);
                    println!("CID:        {}", vm.cid);
                    println!("vCPUs:      {}", vm.vcpu_count);
                    println!("Memory:     {} MiB", vm.mem_size_mib);
                    if let Some(pid) = vm.pid {
                        println!("PID:        {}", pid);
                    }
                    if let Some(ref sock) = vm.socket_path {
                        println!("API Socket: {}", sock);
                    }
                    if let Some(ref uds) = vm.uds_path {
                        println!("vsock UDS:  {}", uds);
                    }
                    if let Some(ref log) = vm.console_log_path {
                        println!("Console:    {}", log);
                    }
                    if let Some(ref network) = detail.network {
                        println!("Network:");
                        println!("  IP Address: {}", network.ip_address);
                        println!("  Bridge:     {}", network.bridge_name);
                    }
                    println!("Created:    {}", format_timestamp(vm.created_at));
                    if let Some(ts) = vm.started_at {
                        println!("Started:    {}", format_timestamp(ts));
                    }
                    if let Some(ts) = vm.stopped_at {
                        println!("Stopped:    {}", format_timestamp(ts));
                    }

                    // Look up attached drives and base image
                    if let Ok(drives) = client.list_drives(None).await {
                        let attached: Vec<_> = drives.iter()
                            .filter(|d| d.vm_id.as_ref() == Some(&vm.id))
                            .collect();
                        if !attached.is_empty() {
                            println!();
                            for d in &attached {
                                let drive_name = d.name.as_deref().unwrap_or("(unnamed)");
                                let device_type = if d.is_root_device { "root" } else { "data" };
                                print!("Drive:      {} ({})", drive_name, device_type);
                                // Resolve base image name
                                if let Some(ref img_id) = d.master_image_id {
                                    if let Ok(Some(img)) = client.get_image(&img_id.encode()).await {
                                        print!(" from image \"{}\"", img.name);
                                    }
                                }
                                println!();
                            }
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
        VmAction::Start { name } => {
            match client.start_vm(&name).await {
                Ok(vm) => {
                    println!("Started VM \"{}\" (state: {}, PID: {})",
                        vm.name, vm.state, vm.pid.unwrap_or(0));
                    println!("\n  View logs:     nexusctl vm logs {}", vm.name);
                    println!("  Stop it:       nexusctl vm stop {}", vm.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot start VM \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_CONFLICT)
                }
            }
        }
        VmAction::Stop { name, force: _ } => {
            match client.stop_vm(&name).await {
                Ok(vm) => {
                    println!("Stopped VM \"{}\" (state: {})", vm.name, vm.state);
                    println!("\n  Restart it: nexusctl vm start {}", vm.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot stop VM \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_CONFLICT)
                }
            }
        }
        VmAction::Logs { name, tail } => {
            match client.vm_logs(&name, Some(tail)).await {
                Ok(logs) => {
                    print!("{logs}");
                    if !logs.ends_with('\n') {
                        println!();
                    }
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot get logs for VM \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        VmAction::History { name } => {
            match client.get_vm_history(&name).await {
                Ok(history) => {
                    if history.is_empty() {
                        println!("No state transitions recorded for VM '{}'", name);
                        return ExitCode::SUCCESS;
                    }

                    // Print table header
                    println!("{:<20} {:<12} {:<12} REASON", "TIMESTAMP", "FROM", "TO");

                    for record in history {
                        // Convert Unix timestamp to human-readable format
                        // chrono is already a dependency (nexusctl/Cargo.toml line 13)
                        let dt = chrono::DateTime::from_timestamp(record.transitioned_at, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| record.transitioned_at.to_string());

                        let reason = record.reason.as_deref().unwrap_or("-");
                        println!("{:<20} {:<12} {:<12} {}", dt, record.from_state, record.to_state, reason);
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
        VmAction::AddProvisionFile { vm, guest_path, host_path, content, encoding, mode } => {
            let (source_type, source) = if let Some(hp) = host_path {
                ("host_path".to_string(), hp)
            } else if let Some(c) = content {
                ("inline".to_string(), c)
            } else {
                eprintln!("Error: either --host-path or --content is required");
                return ExitCode::from(EXIT_GENERAL_ERROR);
            };

            let params = nexus_lib::vm::AddProvisionFileParams {
                guest_path: guest_path.clone(),
                source_type,
                source,
                encoding,
                mode,
            };

            match client.add_provision_file(&vm, &params).await {
                Ok(pf) => {
                    println!("Added provision file for VM \"{}\"", vm);
                    println!("  Guest path: {}", pf.guest_path);
                    println!("  Source:     {} ({})", pf.source, pf.source_type);
                    println!("  Encoding:  {}", pf.encoding);
                    if let Some(ref m) = pf.mode {
                        println!("  Mode:      {}", m);
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
        VmAction::ProvisionFiles { vm } => {
            match client.list_provision_files(&vm).await {
                Ok(files) => {
                    if files.is_empty() {
                        println!("No provision files configured for VM '{}'", vm);
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<40} {:<12} {:<10} {:<8} SOURCE", "GUEST PATH", "TYPE", "ENCODING", "MODE");
                    for pf in &files {
                        let mode = pf.mode.as_deref().unwrap_or("-");
                        let source_display = if pf.source.len() > 40 {
                            format!("{}...", &pf.source[..37])
                        } else {
                            pf.source.clone()
                        };
                        println!("{:<40} {:<12} {:<10} {:<8} {}", pf.guest_path, pf.source_type, pf.encoding, mode, source_display);
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
        VmAction::RemoveProvisionFile { vm, guest_path } => {
            match client.remove_provision_file(&vm, &guest_path).await {
                Ok(true) => {
                    println!("Removed provision file '{}' from VM '{}'", guest_path, vm);
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: no provision file '{}' found for VM '{}'", guest_path, vm);
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
        VmAction::FromRootfs { distro, version, name, role, vcpu, mem, overlays, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Download rootfs {} {}", distro, version);
                println!("  2. Create ephemeral template");
                if !overlays.is_empty() {
                    println!("     Overlays: {} files", overlays.len());
                }
                println!("  3. Trigger build");
                println!("  4. Wait for build completion");
                println!("  5. Create drive from image");
                println!("  6. Create VM \"{}\" (role: {}, vcpu: {}, mem: {}M)",
                    name.as_ref().unwrap_or(&"vm-<timestamp>".to_string()), role, vcpu, mem);
                println!("  7. Attach drive to VM as root device");
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            eprintln!("Downloading rootfs {} {}...", distro, version);

            // Step 1: Download rootfs
            let _rootfs = match client.download_rootfs(&distro, &version).await {
                Ok(r) => {
                    eprintln!("Downloaded rootfs {}-{}", r.distro, r.version);
                    r
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot download rootfs {} {}\n  {}", distro, version, e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 2: Create ephemeral template
            let template_name = format!("_ephemeral_{}_{}_{}",
                distro, version, chrono::Utc::now().timestamp());

            let overlay_map = if overlays.is_empty() {
                None
            } else {
                let mut map = std::collections::HashMap::new();
                for entry in &overlays {
                    if let Some((path, content)) = entry.split_once('=') {
                        map.insert(path.to_string(), content.to_string());
                    } else {
                        eprintln!("Error: invalid overlay format '{}' (expected PATH=CONTENT)", entry);
                        return ExitCode::from(EXIT_GENERAL_ERROR);
                    }
                }
                Some(map)
            };

            eprintln!("Creating ephemeral template...");
            let template_params = CreateTemplateParams {
                name: template_name.clone(),
                source_type: "rootfs".to_string(),
                source_identifier: format!("{}-{}", distro, version),
                overlays: overlay_map,
            };

            let template = match client.create_template(&template_params).await {
                Ok(t) => {
                    eprintln!("Created template \"{}\"", t.name);
                    t
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create template\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 3: Trigger build
            eprintln!("Triggering build...");
            let build = match client.trigger_build(&template.name).await {
                Ok(b) => b,
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot trigger build\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 4: Wait for build completion
            let build_id = build.id.encode();
            let start_time = std::time::Instant::now();
            if let Err(code) = poll_build_completion(&client, &build_id, start_time).await {
                return code;
            }

            // Step 5: Get the completed build to find master_image_id
            let completed_build = match client.get_build(&build_id).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    eprintln!("Error: build {} disappeared after completion", build_id);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
                Err(e) => {
                    eprintln!("Error: cannot get build: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let image_id = match completed_build.master_image_id {
                Some(id) => id,
                None => {
                    eprintln!("Error: build completed but no master image created");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 6: Create drive from image
            eprintln!("Creating drive...");
            let drive_name = name.as_ref().map(|n| format!("{}-drive", n));
            let drive_params = CreateDriveParams {
                name: drive_name.clone(),
                base: image_id.encode(),
                size: None,
            };

            let drive = match client.create_drive(&drive_params).await {
                Ok(d) => {
                    let id_fallback = d.id.encode();
                    let d_name = d.name.as_deref().unwrap_or(&id_fallback);
                    eprintln!("Created drive \"{}\"", d_name);
                    d
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create drive\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 7: Create VM
            eprintln!("Creating VM...");
            let vm_name = name.unwrap_or_else(|| format!("vm-{}", chrono::Utc::now().timestamp()));

            let role_parsed: VmRole = match role.parse() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let vm_params = CreateVmParams {
                name: vm_name.clone(),
                role: role_parsed,
                vcpu_count: vcpu,
                mem_size_mib: mem,
            };

            let vm = match client.create_vm(&vm_params).await {
                Ok(v) => {
                    eprintln!("Created VM \"{}\"", v.name);
                    v
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create VM\n  {}", e);
                    return ExitCode::from(EXIT_CONFLICT);
                }
            };

            // Step 8: Attach drive to VM
            eprintln!("Attaching drive...");
            let drive_id_encoded = drive.id.encode();
            let drive_id_or_name = drive.name.as_deref().unwrap_or(&drive_id_encoded);
            match client.attach_drive(drive_id_or_name, &vm.id.encode(), true).await {
                Ok(_) => {
                    println!("Created VM \"{}\" (state: {}, CID: {})", vm.name, vm.state, vm.cid);
                    println!("\n  Start it: nexusctl vm start {}", vm.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot attach drive\n  {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }

        VmAction::FromTemplate { template, name, role, vcpu, mem, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Trigger build from template \"{}\"", template);
                println!("  2. Wait for build completion");
                println!("  3. Create drive from image");
                println!("  4. Create VM \"{}\" (role: {}, vcpu: {}, mem: {}M)",
                    name.as_ref().unwrap_or(&"vm-<timestamp>".to_string()), role, vcpu, mem);
                println!("  5. Attach drive to VM as root device");
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            // Step 1: Trigger build
            eprintln!("Triggering build from template \"{}\"...", template);
            let build = match client.trigger_build(&template).await {
                Ok(b) => b,
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot trigger build\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 2: Wait for build completion
            let build_id = build.id.encode();
            let start_time = std::time::Instant::now();
            if let Err(code) = poll_build_completion(&client, &build_id, start_time).await {
                return code;
            }

            // Step 3: Get completed build to find image ID
            let completed_build = match client.get_build(&build_id).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    eprintln!("Error: build {} disappeared after completion", build_id);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
                Err(e) => {
                    eprintln!("Error: cannot get build: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let image_id = match completed_build.master_image_id {
                Some(id) => id,
                None => {
                    eprintln!("Error: build completed but no master image created");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 4: Create drive from image
            eprintln!("Creating drive...");
            let drive_name = name.as_ref().map(|n| format!("{}-drive", n));
            let drive_params = CreateDriveParams {
                name: drive_name.clone(),
                base: image_id.encode(),
                size: None,
            };

            let drive = match client.create_drive(&drive_params).await {
                Ok(d) => {
                    let id_fallback = d.id.encode();
                    let d_name = d.name.as_deref().unwrap_or(&id_fallback);
                    eprintln!("Created drive \"{}\"", d_name);
                    d
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create drive\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 5: Create VM
            eprintln!("Creating VM...");
            let vm_name = name.unwrap_or_else(|| format!("vm-{}", chrono::Utc::now().timestamp()));

            let role_parsed: VmRole = match role.parse() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let vm_params = CreateVmParams {
                name: vm_name.clone(),
                role: role_parsed,
                vcpu_count: vcpu,
                mem_size_mib: mem,
            };

            let vm = match client.create_vm(&vm_params).await {
                Ok(v) => {
                    eprintln!("Created VM \"{}\"", v.name);
                    v
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create VM\n  {}", e);
                    return ExitCode::from(EXIT_CONFLICT);
                }
            };

            // Step 6: Attach drive
            eprintln!("Attaching drive...");
            let drive_id_encoded = drive.id.encode();
            let drive_id_or_name = drive.name.as_deref().unwrap_or(&drive_id_encoded);
            match client.attach_drive(drive_id_or_name, &vm.id.encode(), true).await {
                Ok(_) => {
                    println!("Created VM \"{}\" (state: {}, CID: {})", vm.name, vm.state, vm.cid);
                    println!("\n  Start it: nexusctl vm start {}", vm.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot attach drive\n  {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }

        VmAction::FromImage { image, name, role, vcpu, mem, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Create drive from image \"{}\"", image);
                println!("  2. Create VM \"{}\" (role: {}, vcpu: {}, mem: {}M)",
                    name.as_ref().unwrap_or(&"vm-<timestamp>".to_string()), role, vcpu, mem);
                println!("  3. Attach drive to VM as root device");
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            // Step 1: Create drive from image
            eprintln!("Creating drive from image \"{}\"...", image);
            let drive_name = name.as_ref().map(|n| format!("{}-drive", n));
            let drive_params = CreateDriveParams {
                name: drive_name.clone(),
                base: image.clone(),
                size: None,
            };

            let drive = match client.create_drive(&drive_params).await {
                Ok(d) => {
                    let id_fallback = d.id.encode();
                    let d_name = d.name.as_deref().unwrap_or(&id_fallback);
                    eprintln!("Created drive \"{}\"", d_name);
                    d
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create drive\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 2: Create VM
            eprintln!("Creating VM...");
            let vm_name = name.unwrap_or_else(|| format!("vm-{}", chrono::Utc::now().timestamp()));

            let role_parsed: VmRole = match role.parse() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let vm_params = CreateVmParams {
                name: vm_name.clone(),
                role: role_parsed,
                vcpu_count: vcpu,
                mem_size_mib: mem,
            };

            let vm = match client.create_vm(&vm_params).await {
                Ok(v) => {
                    eprintln!("Created VM \"{}\"", v.name);
                    v
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create VM\n  {}", e);
                    return ExitCode::from(EXIT_CONFLICT);
                }
            };

            // Step 3: Attach drive
            eprintln!("Attaching drive...");
            let drive_id_encoded = drive.id.encode();
            let drive_id_or_name = drive.name.as_deref().unwrap_or(&drive_id_encoded);
            match client.attach_drive(drive_id_or_name, &vm.id.encode(), true).await {
                Ok(_) => {
                    println!("Created VM \"{}\" (state: {}, CID: {})", vm.name, vm.state, vm.cid);
                    println!("\n  Start it: nexusctl vm start {}", vm.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot attach drive\n  {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
    }
}

async fn cmd_image(daemon_addr: &str, action: ImageAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        ImageAction::List => {
            match client.list_images().await {
                Ok(imgs) => {
                    if imgs.is_empty() {
                        println!("No images found.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<13} {:<20} {:<50}", "ID", "NAME", "PATH");
                    for img in &imgs {
                        println!("{:<13} {:<20} {:<50}", img.id, img.name, img.subvolume_path);
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
        ImageAction::Import { path, name } => {
            let params = ImportImageParams {
                name: name.clone(),
                source_path: path.clone(),
            };
            match client.import_image(&params).await {
                Ok(img) => {
                    println!("Imported image \"{}\"", img.name);
                    println!("  Path: {}", img.subvolume_path);
                    println!("\n  Create a drive: nexusctl drive create --base {} --name my-drive", img.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot import image \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        ImageAction::Inspect { name } => {
            match client.get_image(&name).await {
                Ok(Some(img)) => {
                    println!("Name:       {}", img.name);
                    println!("ID:         {}", img.id);
                    println!("Path:       {}", img.subvolume_path);
                    if let Some(size) = img.size_bytes {
                        println!("Size:       {} bytes", size);
                    }
                    println!("Created:    {}", format_timestamp(img.created_at));
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: image \"{}\" not found", name);
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
        ImageAction::Delete { name, yes } => {
            if !yes {
                eprintln!(
                    "Error: refusing to delete image without confirmation\n  \
                     Run with --yes to skip confirmation: nexusctl image delete {} --yes",
                    name
                );
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
            match client.delete_image(&name).await {
                Ok(true) => {
                    println!("Deleted image \"{}\"", name);
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: image \"{}\" not found", name);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot delete image \"{}\"\n  {e}", name);
                    ExitCode::from(EXIT_CONFLICT)
                }
            }
        }

        ImageAction::FromRootfs { distro, version, name: _, overlays, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Download rootfs {} {}", distro, version);
                println!("  2. Create ephemeral template");
                if !overlays.is_empty() {
                    println!("     Overlays: {} files", overlays.len());
                }
                println!("  3. Trigger build");
                println!("  4. Wait for build completion");
                println!("  5. Image registered");
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            eprintln!("Downloading rootfs {} {}...", distro, version);

            // Step 1: Download rootfs
            let _rootfs = match client.download_rootfs(&distro, &version).await {
                Ok(r) => {
                    eprintln!("Downloaded rootfs {}-{}", r.distro, r.version);
                    r
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot download rootfs {} {}\n  {}", distro, version, e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 2: Create ephemeral template
            let template_name = format!("_ephemeral_{}_{}_{}",
                distro, version, chrono::Utc::now().timestamp());

            let overlay_map = if overlays.is_empty() {
                None
            } else {
                let mut map = std::collections::HashMap::new();
                for entry in &overlays {
                    if let Some((path, content)) = entry.split_once('=') {
                        map.insert(path.to_string(), content.to_string());
                    } else {
                        eprintln!("Error: invalid overlay format '{}' (expected PATH=CONTENT)", entry);
                        return ExitCode::from(EXIT_GENERAL_ERROR);
                    }
                }
                Some(map)
            };

            eprintln!("Creating ephemeral template...");
            let template_params = CreateTemplateParams {
                name: template_name.clone(),
                source_type: "rootfs".to_string(),
                source_identifier: format!("{}-{}", distro, version),
                overlays: overlay_map,
            };

            let template = match client.create_template(&template_params).await {
                Ok(t) => {
                    eprintln!("Created template \"{}\"", t.name);
                    t
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create template\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 3: Trigger build
            eprintln!("Triggering build...");
            let build = match client.trigger_build(&template.name).await {
                Ok(b) => b,
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot trigger build\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 4: Wait for build completion
            let build_id = build.id.encode();
            let start_time = std::time::Instant::now();
            if let Err(code) = poll_build_completion(&client, &build_id, start_time).await {
                return code;
            }

            // Step 5: Get completed build to find image
            let completed_build = match client.get_build(&build_id).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    eprintln!("Error: build {} disappeared after completion", build_id);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
                Err(e) => {
                    eprintln!("Error: cannot get build: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let image_id = match completed_build.master_image_id {
                Some(id) => id,
                None => {
                    eprintln!("Error: build completed but no master image created");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 6: Get image details
            match client.get_image(&image_id.encode()).await {
                Ok(Some(img)) => {
                    println!("Created image \"{}\"", img.name);
                    println!("  ID:   {}", img.id);
                    println!("  Path: {}", img.subvolume_path);
                    println!("\n  Create a drive: nexusctl drive from-image {}", img.name);
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: image {} not found after build", image_id);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }

        ImageAction::FromTemplate { template, name: _, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Trigger build from template \"{}\"", template);
                println!("  2. Wait for build completion");
                println!("  3. Image registered");
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            // Step 1: Trigger build
            eprintln!("Triggering build from template \"{}\"...", template);
            let build = match client.trigger_build(&template).await {
                Ok(b) => b,
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot trigger build\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 2: Wait for build completion
            let build_id = build.id.encode();
            let start_time = std::time::Instant::now();
            if let Err(code) = poll_build_completion(&client, &build_id, start_time).await {
                return code;
            }

            // Step 3: Get completed build to find image
            let completed_build = match client.get_build(&build_id).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    eprintln!("Error: build {} disappeared after completion", build_id);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
                Err(e) => {
                    eprintln!("Error: cannot get build: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let image_id = match completed_build.master_image_id {
                Some(id) => id,
                None => {
                    eprintln!("Error: build completed but no master image created");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 4: Get image details
            match client.get_image(&image_id.encode()).await {
                Ok(Some(img)) => {
                    println!("Created image \"{}\"", img.name);
                    println!("  ID:   {}", img.id);
                    println!("  Path: {}", img.subvolume_path);
                    println!("\n  Create a drive: nexusctl drive from-image {}", img.name);
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: image {} not found after build", image_id);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
    }
}

async fn cmd_drive(daemon_addr: &str, action: DriveAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        DriveAction::List { base } => {
            match client.list_drives(base.as_deref()).await {
                Ok(drives) => {
                    if drives.is_empty() {
                        println!("No drives found.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<13} {:<20} {:<50} {:<10}", "ID", "NAME", "PATH", "READ-ONLY");
                    for drive in &drives {
                        let name = drive.name.as_deref().unwrap_or("(unnamed)");
                        let ro = if drive.is_read_only { "yes" } else { "no" };
                        println!("{:<13} {:<20} {:<50} {:<10}", drive.id, name, drive.subvolume_path, ro);
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
        DriveAction::Create { name, base, size } => {
            // Parse size if provided
            let size_bytes = match size {
                Some(ref s) => match nexus_lib::drive::parse_size(s) {
                    Ok(bytes) => Some(bytes),
                    Err(e) => {
                        eprintln!("Error: invalid size '{}': {}", s, e);
                        return ExitCode::from(EXIT_GENERAL_ERROR);
                    }
                },
                None => None,
            };

            let params = CreateDriveParams {
                name: name.clone(),
                base: base.clone(),
                size: size_bytes,
            };
            match client.create_drive(&params).await {
                Ok(drive) => {
                    let id_fallback = drive.id.encode();
                    let drive_name = drive.name.as_deref().unwrap_or(&id_fallback);
                    println!("Created drive \"{}\" from base \"{}\"", drive_name, base);
                    println!("  Path: {}", drive.subvolume_path);
                    if let Some(s) = size_bytes {
                        let mb = s / (1024 * 1024);
                        println!("  Size: {}M", mb);
                    }
                    println!("\n  Inspect it: nexusctl drive inspect {}", drive_name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot create drive\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        DriveAction::Inspect { name } => {
            match client.get_drive(&name).await {
                Ok(Some(drive)) => {
                    let drive_name = drive.name.as_deref().unwrap_or("(unnamed)");
                    println!("Name:       {}", drive_name);
                    println!("ID:         {}", drive.id);
                    println!("Path:       {}", drive.subvolume_path);
                    if let Some(ref img_id) = drive.master_image_id {
                        println!("Base Image: {}", img_id);
                    }
                    if let Some(ref vm_id) = drive.vm_id {
                        println!("Attached:   VM {}", vm_id);
                    } else {
                        println!("Attached:   (none)");
                    }
                    println!("Read-Only:  {}", if drive.is_read_only { "yes" } else { "no" });
                    println!("Root Dev:   {}", if drive.is_root_device { "yes" } else { "no" });
                    if let Some(size) = drive.size_bytes {
                        println!("Size:       {} bytes", size);
                    }
                    println!("Created:    {}", format_timestamp(drive.created_at));
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: drive \"{}\" not found", name);
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
        DriveAction::Delete { name, yes } => {
            if !yes {
                eprintln!(
                    "Error: refusing to delete drive without confirmation\n  \
                     Run with --yes to skip confirmation: nexusctl drive delete {} --yes",
                    name
                );
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
            match client.delete_drive(&name).await {
                Ok(true) => {
                    println!("Deleted drive \"{}\"", name);
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: drive \"{}\" not found", name);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot delete drive \"{}\"\n  {e}", name);
                    ExitCode::from(EXIT_CONFLICT)
                }
            }
        }
        DriveAction::Attach { name, vm, root } => {
            // Resolve the VM name to an ID
            let vm_id = match client.get_vm(&vm).await {
                Ok(Some(vm)) => vm.id,
                Ok(None) => {
                    eprintln!("Error: VM \"{}\" not found", vm);
                    return ExitCode::from(EXIT_NOT_FOUND);
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            match client.attach_drive(&name, &vm_id.encode(), root).await {
                Ok(drive) => {
                    let id_fallback = drive.id.encode();
                    let drive_name = drive.name.as_deref().unwrap_or(&id_fallback);
                    println!("Attached drive \"{}\" to VM \"{}\"", drive_name, vm);
                    if root {
                        println!("  Root device: yes");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot attach drive \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        DriveAction::Detach { name } => {
            match client.detach_drive(&name).await {
                Ok(drive) => {
                    let id_fallback = drive.id.encode();
                    let drive_name = drive.name.as_deref().unwrap_or(&id_fallback);
                    println!("Detached drive \"{}\"", drive_name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot detach drive \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }

        DriveAction::FromRootfs { distro, version, name, overlays, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Download rootfs {} {}", distro, version);
                println!("  2. Create ephemeral template");
                if !overlays.is_empty() {
                    println!("     Overlays: {} files", overlays.len());
                }
                println!("  3. Trigger build");
                println!("  4. Wait for build completion");
                println!("  5. Create drive \"{}\" from image", name.as_ref().unwrap_or(&"<auto-generated>".to_string()));
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            eprintln!("Downloading rootfs {} {}...", distro, version);

            // Step 1: Download rootfs
            let _rootfs = match client.download_rootfs(&distro, &version).await {
                Ok(r) => {
                    eprintln!("Downloaded rootfs {}-{}", r.distro, r.version);
                    r
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot download rootfs {} {}\n  {}", distro, version, e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 2: Create ephemeral template
            let template_name = format!("_ephemeral_{}_{}_{}",
                distro, version, chrono::Utc::now().timestamp());

            let overlay_map = if overlays.is_empty() {
                None
            } else {
                let mut map = std::collections::HashMap::new();
                for entry in &overlays {
                    if let Some((path, content)) = entry.split_once('=') {
                        map.insert(path.to_string(), content.to_string());
                    } else {
                        eprintln!("Error: invalid overlay format '{}' (expected PATH=CONTENT)", entry);
                        return ExitCode::from(EXIT_GENERAL_ERROR);
                    }
                }
                Some(map)
            };

            eprintln!("Creating ephemeral template...");
            let template_params = CreateTemplateParams {
                name: template_name.clone(),
                source_type: "rootfs".to_string(),
                source_identifier: format!("{}-{}", distro, version),
                overlays: overlay_map,
            };

            let template = match client.create_template(&template_params).await {
                Ok(t) => {
                    eprintln!("Created template \"{}\"", t.name);
                    t
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot create template\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 3: Trigger build
            eprintln!("Triggering build...");
            let build = match client.trigger_build(&template.name).await {
                Ok(b) => b,
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot trigger build\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 4: Wait for build completion
            let build_id = build.id.encode();
            let start_time = std::time::Instant::now();
            if let Err(code) = poll_build_completion(&client, &build_id, start_time).await {
                return code;
            }

            // Step 5: Get completed build to find image ID
            let completed_build = match client.get_build(&build_id).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    eprintln!("Error: build {} disappeared after completion", build_id);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
                Err(e) => {
                    eprintln!("Error: cannot get build: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let image_id = match completed_build.master_image_id {
                Some(id) => id,
                None => {
                    eprintln!("Error: build completed but no master image created");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 6: Create drive
            eprintln!("Creating drive...");
            let drive_params = CreateDriveParams {
                name: name.clone(),
                base: image_id.encode(),
                size: None,
            };

            match client.create_drive(&drive_params).await {
                Ok(drive) => {
                    let id_fallback = drive.id.encode();
                    let drive_name = drive.name.as_deref().unwrap_or(&id_fallback);
                    println!("Created drive \"{}\"", drive_name);
                    println!("\n  Inspect it: nexusctl drive inspect {}", drive_name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot create drive\n  {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }

        DriveAction::FromTemplate { template, name, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Trigger build from template \"{}\"", template);
                println!("  2. Wait for build completion");
                println!("  3. Create drive \"{}\" from image", name.as_ref().unwrap_or(&"<auto-generated>".to_string()));
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            // Step 1: Trigger build
            eprintln!("Triggering build from template \"{}\"...", template);
            let build = match client.trigger_build(&template).await {
                Ok(b) => b,
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    return ExitCode::from(EXIT_DAEMON_UNREACHABLE);
                }
                Err(e) => {
                    eprintln!("Error: cannot trigger build\n  {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 2: Wait for build completion
            let build_id = build.id.encode();
            let start_time = std::time::Instant::now();
            if let Err(code) = poll_build_completion(&client, &build_id, start_time).await {
                return code;
            }

            // Step 3: Get completed build to find image ID
            let completed_build = match client.get_build(&build_id).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    eprintln!("Error: build {} disappeared after completion", build_id);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
                Err(e) => {
                    eprintln!("Error: cannot get build: {}", e);
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            let image_id = match completed_build.master_image_id {
                Some(id) => id,
                None => {
                    eprintln!("Error: build completed but no master image created");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
            };

            // Step 4: Create drive
            eprintln!("Creating drive...");
            let drive_params = CreateDriveParams {
                name: name.clone(),
                base: image_id.encode(),
                size: None,
            };

            match client.create_drive(&drive_params).await {
                Ok(drive) => {
                    let id_fallback = drive.id.encode();
                    let drive_name = drive.name.as_deref().unwrap_or(&id_fallback);
                    println!("Created drive \"{}\"", drive_name);
                    println!("\n  Inspect it: nexusctl drive inspect {}", drive_name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot create drive\n  {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }

        DriveAction::FromImage { image, name, dry_run } => {
            if dry_run {
                println!("Dry run - would execute:");
                println!("  1. Create drive \"{}\" from image \"{}\"",
                    name.as_ref().unwrap_or(&"<auto-generated>".to_string()), image);
                println!("\nNo changes applied (dry run)");
                return ExitCode::SUCCESS;
            }

            eprintln!("Creating drive from image \"{}\"...", image);
            let drive_params = CreateDriveParams {
                name: name.clone(),
                base: image.clone(),
                size: None,
            };

            match client.create_drive(&drive_params).await {
                Ok(drive) => {
                    let id_fallback = drive.id.encode();
                    let drive_name = drive.name.as_deref().unwrap_or(&id_fallback);
                    println!("Created drive \"{}\"", drive_name);
                    println!("\n  Inspect it: nexusctl drive inspect {}", drive_name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot create drive\n  {}", e);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
    }
}

async fn cmd_kernel(daemon_addr: &str, action: KernelAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        KernelAction::List => {
            match client.list_kernels().await {
                Ok(kernels) => {
                    if kernels.is_empty() {
                        println!("No kernels installed.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<15} {:<10} {:<15} {:<10}", "VERSION", "ARCH", "SIZE", "VERIFIED");
                    for k in &kernels {
                        let size = format!("{:.1} MB", k.file_size as f64 / 1_000_000.0);
                        let verified = if k.pgp_verified { "yes" } else { "no" };
                        println!("{:<15} {:<10} {:<15} {:<10}", k.version, k.architecture, size, verified);
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
        KernelAction::Download { version } => {
            println!("Downloading kernel {version}...");
            match client.download_kernel(&version).await {
                Ok(k) => {
                    println!("Downloaded kernel {} ({})", k.version, k.architecture);
                    println!("  Path: {}", k.path_on_host);
                    println!("  SHA256: {}", k.sha256);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot download kernel {version}\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        KernelAction::Installed => {
            match client.list_kernels().await {
                Ok(kernels) => {
                    if kernels.is_empty() {
                        println!("No kernels installed.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<15} {:<10} {:<15}", "VERSION", "ARCH", "SIZE");
                    for k in &kernels {
                        let size = format!("{:.1} MB", k.file_size as f64 / 1_000_000.0);
                        println!("{:<15} {:<10} {:<15}", k.version, k.architecture, size);
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
        KernelAction::Remove { version } => {
            match client.remove_kernel(&version).await {
                Ok(true) => {
                    println!("Removed kernel {version}");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: kernel {version} not found");
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
        KernelAction::Verify { version } => {
            match client.verify_kernel(&version).await {
                Ok(true) => {
                    println!("Kernel {version}: integrity OK");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Kernel {version}: integrity FAILED (hash mismatch)");
                    ExitCode::from(EXIT_GENERAL_ERROR)
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
    }
}

async fn cmd_rootfs(daemon_addr: &str, action: RootfsAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        RootfsAction::List { distro } => {
            eprintln!("Note: listing available versions for {distro} requires network access");
            eprintln!("Use 'nexusctl rootfs download {distro} <version>' to download a specific version");
            ExitCode::SUCCESS
        }
        RootfsAction::Download { distro, version } => {
            println!("Downloading rootfs {distro} {version}...");
            match client.download_rootfs(&distro, &version).await {
                Ok(r) => {
                    println!("Downloaded rootfs {}-{} ({})", r.distro, r.version, r.architecture);
                    println!("  Path: {}", r.path_on_host);
                    println!("  SHA256: {}", r.sha256);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot download rootfs {distro} {version}\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        RootfsAction::Installed => {
            match client.list_rootfs().await {
                Ok(images) => {
                    if images.is_empty() {
                        println!("No rootfs images installed.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<12} {:<10} {:<10} {:<15}", "DISTRO", "VERSION", "ARCH", "SIZE");
                    for r in &images {
                        let size = format!("{:.1} MB", r.file_size as f64 / 1_000_000.0);
                        println!("{:<12} {:<10} {:<10} {:<15}", r.distro, r.version, r.architecture, size);
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
        RootfsAction::Remove { distro, version } => {
            match client.remove_rootfs(&distro, &version).await {
                Ok(true) => {
                    println!("Removed rootfs {distro} {version}");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: rootfs {distro} {version} not found");
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
    }
}

async fn cmd_firecracker(daemon_addr: &str, action: FirecrackerAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        FirecrackerAction::List => {
            match client.list_firecracker().await {
                Ok(versions) => {
                    if versions.is_empty() {
                        println!("No Firecracker binaries installed.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<12} {:<10} {:<15}", "VERSION", "ARCH", "SIZE");
                    for fc in &versions {
                        let size = format!("{:.1} MB", fc.file_size as f64 / 1_000_000.0);
                        println!("{:<12} {:<10} {:<15}", fc.version, fc.architecture, size);
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
        FirecrackerAction::Download { version } => {
            println!("Downloading Firecracker {version}...");
            match client.download_firecracker(&version).await {
                Ok(fc) => {
                    println!("Downloaded Firecracker {} ({})", fc.version, fc.architecture);
                    println!("  Path: {}", fc.path_on_host);
                    println!("  SHA256: {}", fc.sha256);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot download Firecracker {version}\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        FirecrackerAction::Installed => {
            match client.list_firecracker().await {
                Ok(versions) => {
                    if versions.is_empty() {
                        println!("No Firecracker binaries installed.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<12} {:<10} {:<15}", "VERSION", "ARCH", "SIZE");
                    for fc in &versions {
                        let size = format!("{:.1} MB", fc.file_size as f64 / 1_000_000.0);
                        println!("{:<12} {:<10} {:<15}", fc.version, fc.architecture, size);
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
        FirecrackerAction::Remove { version } => {
            match client.remove_firecracker(&version).await {
                Ok(true) => {
                    println!("Removed Firecracker {version}");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: Firecracker {version} not found");
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
    }
}

async fn cmd_template(daemon_addr: &str, action: TemplateAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        TemplateAction::List => {
            match client.list_templates().await {
                Ok(tpls) => {
                    if tpls.is_empty() {
                        println!("No templates found.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<20} {:<8} {:<10} {:<50}", "NAME", "VERSION", "TYPE", "SOURCE");
                    for tpl in &tpls {
                        let source = if tpl.source_identifier.len() > 48 {
                            format!("{}...", &tpl.source_identifier[..45])
                        } else {
                            tpl.source_identifier.clone()
                        };
                        println!("{:<20} {:<8} {:<10} {:<50}", tpl.name, tpl.version, tpl.source_type, source);
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
        TemplateAction::Create { name, source_type, source, overlays } => {
            let overlay_map = if overlays.is_empty() {
                None
            } else {
                let mut map = std::collections::HashMap::new();
                for entry in &overlays {
                    if let Some((path, content)) = entry.split_once('=') {
                        map.insert(path.to_string(), content.to_string());
                    } else {
                        eprintln!("Error: invalid overlay format '{}' (expected PATH=CONTENT)", entry);
                        return ExitCode::from(EXIT_GENERAL_ERROR);
                    }
                }
                Some(map)
            };

            let params = CreateTemplateParams {
                name: name.clone(),
                source_type,
                source_identifier: source,
                overlays: overlay_map,
            };
            match client.create_template(&params).await {
                Ok(tpl) => {
                    println!("Created template \"{}\" (version {})", tpl.name, tpl.version);
                    println!("\n  Trigger a build: nexusctl build trigger {}", tpl.name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot create template \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        TemplateAction::Inspect { name } => {
            match client.get_template(&name).await {
                Ok(Some(tpl)) => {
                    println!("Name:       {}", tpl.name);
                    println!("ID:         {}", tpl.id);
                    println!("Version:    {}", tpl.version);
                    println!("Source:     {} ({})", tpl.source_identifier, tpl.source_type);
                    if let Some(ref overlays) = tpl.overlays {
                        println!("Overlays:   {} files", overlays.len());
                        for path in overlays.keys() {
                            println!("  {}", path);
                        }
                    }
                    println!("Created:    {}", format_timestamp(tpl.created_at));
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: template \"{}\" not found", name);
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
        TemplateAction::Delete { name, yes } => {
            if !yes {
                eprintln!(
                    "Error: refusing to delete template without confirmation\n  \
                     Run with --yes to skip confirmation: nexusctl template delete {} --yes",
                    name
                );
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
            match client.delete_template(&name).await {
                Ok(true) => {
                    println!("Deleted template \"{}\"", name);
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: template \"{}\" not found", name);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot delete template \"{}\"\n  {e}", name);
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
    }
}

async fn cmd_build(daemon_addr: &str, action: BuildAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        BuildAction::Trigger { template } => {
            match client.trigger_build(&template).await {
                Ok(build) => {
                    let id_str = build.id.encode();
                    let short_id = &id_str[..std::cmp::min(8, id_str.len())];
                    println!("Build triggered (ID: {})", short_id);
                    println!("  Template: {} (version {})", build.name, build.template_version);
                    println!("  Status:   {}", build.status);
                    println!("\n  Check progress: nexusctl build inspect {}", id_str);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot trigger build\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        BuildAction::List { template } => {
            match client.list_builds(template.as_deref()).await {
                Ok(builds) => {
                    if builds.is_empty() {
                        println!("No builds found.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<10} {:<20} {:<10} {:<20}", "ID", "TEMPLATE", "STATUS", "CREATED");
                    for build in &builds {
                        let id_str = build.id.encode();
                        let short_id = &id_str[..std::cmp::min(8, id_str.len())];
                        println!(
                            "{:<10} {:<20} {:<10} {:<20}",
                            short_id, build.name, build.status, format_timestamp(build.created_at),
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
        BuildAction::Inspect { id } => {
            match client.get_build(&id).await {
                Ok(Some(build)) => {
                    println!("Build ID:     {}", build.id);
                    println!("Template:     {} (version {})", build.name, build.template_version);
                    println!("Status:       {}", build.status);
                    println!("Source:       {} ({})", build.source_identifier, build.source_type);
                    if let Some(ref img_id) = build.master_image_id {
                        println!("Master Image: {}", img_id);
                    }
                    if let Some(ref log) = build.build_log_path {
                        println!("Log:          {}", log);
                    }
                    println!("Created:      {}", format_timestamp(build.created_at));
                    if let Some(completed) = build.completed_at {
                        println!("Completed:    {}", format_timestamp(completed));
                    }
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: build \"{}\" not found", id);
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

/// Poll a build until completion, displaying progress
async fn poll_build_completion(
    client: &NexusClient,
    build_id: &str,
    start_time: std::time::Instant,
) -> Result<(), ExitCode> {
    use std::io::{self, Write};
    use tokio::time::{sleep, Duration};

    loop {
        match client.get_build(build_id).await {
            Ok(Some(build)) => {
                let elapsed = start_time.elapsed().as_secs_f32();
                match build.status {
                    nexus_lib::template::BuildStatus::Success => {
                        eprintln!("\rBuild complete ({:.1}s)", elapsed);
                        return Ok(());
                    }
                    nexus_lib::template::BuildStatus::Failed => {
                        eprintln!("\rBuild failed");
                        if let Some(log_path) = build.build_log_path {
                            eprintln!("  Log: {}", log_path);
                        }
                        return Err(ExitCode::from(EXIT_GENERAL_ERROR));
                    }
                    nexus_lib::template::BuildStatus::Building => {
                        eprint!("\rBuilding image ({:.1}s elapsed)...", elapsed);
                        io::stderr().flush().ok();
                        sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            Ok(None) => {
                eprintln!("\rBuild {} not found", build_id);
                return Err(ExitCode::from(EXIT_NOT_FOUND));
            }
            Err(e) if e.is_connect() => {
                eprintln!("\rLost connection to daemon during build");
                return Err(ExitCode::from(EXIT_DAEMON_UNREACHABLE));
            }
            Err(e) => {
                eprintln!("\rError polling build: {}", e);
                return Err(ExitCode::from(EXIT_GENERAL_ERROR));
            }
        }
    }
}

// TODO: read bridge_name and subnet from a preferences table once it exists
const BRIDGE_NAME: &str = "nexbr0";
const VM_SUBNET: &str = "172.16.0.0/12";

async fn cmd_admin(daemon_addr: &str, action: AdminAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        AdminAction::CleanupNetwork => {
            match client.admin_cleanup_network().await {
                Ok(report) => {
                    println!("Network cleanup complete:");
                    println!("  Taps deleted:    {}", report.taps_deleted);
                    println!("  Bridge deleted:  {}", report.bridge_deleted);
                    println!("  nftables flushed: {}", report.nftables_flushed);
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
    }
}

async fn cmd_config(daemon_addr: &str, cmd: ConfigCommands) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match cmd {
        ConfigCommands::Get { key } => {
            // Convert kebab-case to snake_case for internal setting names
            let setting_key = key.replace('-', "_");

            match client.get_setting(&setting_key).await {
                Ok(value) => {
                    println!("{}", value);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_not_found() => {
                    eprintln!("Setting '{}' not found", key);
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

        ConfigCommands::Set { key, value } => {
            // Convert kebab-case to snake_case for internal setting names
            let setting_key = key.replace('-', "_");

            // Special handling for service_port: read-modify-write the JSON map
            // Usage: nexusctl config set service-port <name> <port>
            if setting_key == "service_port" {
                if value.len() != 2 {
                    eprintln!("Usage: nexusctl config set service-port <name> <port>");
                    return ExitCode::from(EXIT_GENERAL_ERROR);
                }
                let svc_name = &value[0];
                let port: u16 = match value[1].parse() {
                    Ok(p) if p > 0 => p,
                    _ => {
                        eprintln!("Error: port must be 1-65535");
                        return ExitCode::from(EXIT_GENERAL_ERROR);
                    }
                };

                // Read current service_ports (or start from default)
                let current = client.get_setting("service_ports").await.ok();
                let mut ports_map = match &current {
                    Some(val) => {
                        let json: serde_json::Value = match serde_json::from_str(val) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("Error: invalid service_ports JSON: {e}");
                                return ExitCode::from(EXIT_GENERAL_ERROR);
                            }
                        };
                        match json.get("ports").and_then(|p| p.as_object()) {
                            Some(m) => m.clone(),
                            None => serde_json::Map::new(),
                        }
                    }
                    None => serde_json::Map::new(),
                };

                ports_map.insert(svc_name.clone(), json!(port));

                let final_value = json!({
                    "version": 1,
                    "ports": ports_map
                }).to_string();

                return match client.set_setting("service_ports", &final_value).await {
                    Ok(_) => {
                        println!("Service port '{}' set to {}", svc_name, port);
                        ExitCode::SUCCESS
                    }
                    Err(e) if e.is_connect() => {
                        print_connect_error(daemon_addr);
                        ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                    }
                    Err(e) => {
                        eprintln!("Validation error: {e}");
                        ExitCode::from(EXIT_GENERAL_ERROR)
                    }
                };
            }

            let value = value.join(" ");

            // Special handling for dns_servers: convert comma-separated IPs to JSON
            let final_value = if setting_key == "dns_servers" && value != "from-host" && !value.starts_with('{') {
                // Assume comma-separated IPs, convert to JSON
                let servers: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
                let json_value = json!({
                    "version": 1,
                    "servers": servers
                });
                json_value.to_string()
            } else {
                value
            };

            match client.set_setting(&setting_key, &final_value).await {
                Ok(_) => {
                    println!("Setting '{}' updated", key);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Validation error: {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }

        ConfigCommands::List => {
            match client.list_settings().await {
                Ok(settings) => {
                    for (key, value, _type) in settings {
                        // Convert snake_case to kebab-case for display
                        let display_key = key.replace('_', "-");
                        println!("{}: {}", display_key, value);
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
    }
}

async fn cmd_setup_firewall() -> ExitCode {
    use std::process::Command;

    // Must run as root
    // SAFETY: getuid is always safe to call
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: setup-firewall requires root privileges\n  Run with: sudo nexusctl setup-firewall");
        return ExitCode::from(EXIT_GENERAL_ERROR);
    }

    // Check UFW is available and active
    let ufw_status = match Command::new("ufw").arg("status").output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: cannot run ufw: {e}\n  Is ufw installed?");
            return ExitCode::from(EXIT_GENERAL_ERROR);
        }
    };
    let status_text = String::from_utf8_lossy(&ufw_status.stdout);
    if !status_text.contains("Status: active") {
        eprintln!("Error: ufw is not active\n  Enable it with: sudo ufw enable");
        return ExitCode::from(EXIT_GENERAL_ERROR);
    }

    // Check if the rule already exists
    if status_text.contains(BRIDGE_NAME) {
        println!("Firewall rule for {BRIDGE_NAME} already exists, nothing to do.");
        return ExitCode::SUCCESS;
    }

    // Add the UFW route rule
    let rule_args = [
        "route", "allow", "in", "on", BRIDGE_NAME, "from", VM_SUBNET,
    ];
    println!("Adding UFW rule: ufw {}", rule_args.join(" "));
    let result = match Command::new("ufw").args(rule_args).output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: failed to run ufw: {e}");
            return ExitCode::from(EXIT_GENERAL_ERROR);
        }
    };
    if !result.status.success() {
        let err = String::from_utf8_lossy(&result.stderr);
        eprintln!("Error: ufw rule failed: {err}");
        return ExitCode::from(EXIT_GENERAL_ERROR);
    }

    let output = String::from_utf8_lossy(&result.stdout);
    println!("{}", output.trim());
    println!("\nVM traffic from {VM_SUBNET} will now be forwarded through {BRIDGE_NAME}.");
    ExitCode::SUCCESS
}

async fn cmd_mcp_bridge(daemon_addr: &str) -> ExitCode {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);

    let client = reqwest::Client::new();
    let mcp_url = format!("http://{}/mcp", daemon_addr);

    let mut line = String::new();

    loop {
        line.clear();

        // Read JSON-RPC request from stdin
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error reading stdin: {}", e);
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Forward to nexusd via HTTP POST
        let response = match client
            .post(&mcp_url)
            .header("Content-Type", "application/json")
            .body(trimmed.to_string())
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                eprintln!("Error connecting to nexusd: {}", e);
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
        };

        // Get response body
        let body = match response.text().await {
            Ok(text) => text,
            Err(e) => {
                eprintln!("Error reading response: {}", e);
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
        };

        // Write JSON-RPC response to stdout
        if let Err(e) = stdout.write_all(body.as_bytes()).await {
            eprintln!("Error writing to stdout: {}", e);
            return ExitCode::from(EXIT_GENERAL_ERROR);
        }

        if let Err(e) = stdout.write_all(b"\n").await {
            eprintln!("Error writing newline: {}", e);
            return ExitCode::from(EXIT_GENERAL_ERROR);
        }

        if let Err(e) = stdout.flush().await {
            eprintln!("Error flushing stdout: {}", e);
            return ExitCode::from(EXIT_GENERAL_ERROR);
        }
    }

    ExitCode::SUCCESS
}
