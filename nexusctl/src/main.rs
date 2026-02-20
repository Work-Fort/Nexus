// SPDX-License-Identifier: GPL-2.0-only
use clap::{Parser, Subcommand};
use nexus_lib::client::NexusClient;
use nexus_lib::vm::{CreateVmParams, VmRole};
use nexus_lib::template::CreateTemplateParams;
use nexus_lib::workspace::{CreateWorkspaceParams, ImportImageParams};
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
    /// Manage workspaces (alias: workspace)
    #[command(alias = "workspace")]
    Ws {
        #[command(subcommand)]
        action: WsAction,
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
}

#[derive(Subcommand)]
enum WsAction {
    /// List all workspaces
    List {
        /// Filter by base image name
        #[arg(long)]
        base: Option<String>,
    },
    /// Create a workspace from a master image
    Create {
        /// Workspace name
        #[arg(long)]
        name: Option<String>,
        /// Base image name
        #[arg(long)]
        base: String,
    },
    /// Show workspace details
    Inspect {
        /// Workspace name or ID
        name: String,
    },
    /// Delete a workspace
    Delete {
        /// Workspace name or ID
        name: String,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// Attach a workspace to a VM
    Attach {
        /// Workspace name or ID
        name: String,
        /// VM name or ID to attach to
        #[arg(long)]
        vm: String,
        /// Mount as root device
        #[arg(long)]
        root: bool,
    },
    /// Detach a workspace from its VM
    Detach {
        /// Workspace name or ID
        name: String,
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
        Commands::Ws { action } => cmd_ws(&daemon_addr, action).await,
        Commands::Kernel { action } => cmd_kernel(&daemon_addr, action).await,
        Commands::Rootfs { action } => cmd_rootfs(&daemon_addr, action).await,
        Commands::Firecracker { action } => cmd_firecracker(&daemon_addr, action).await,
        Commands::Template { action } => cmd_template(&daemon_addr, action).await,
        Commands::Build { action } => cmd_build(&daemon_addr, action).await,
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
                    println!("Created:    {}", format_timestamp(vm.created_at));
                    if let Some(ts) = vm.started_at {
                        println!("Started:    {}", format_timestamp(ts));
                    }
                    if let Some(ts) = vm.stopped_at {
                        println!("Stopped:    {}", format_timestamp(ts));
                    }

                    // Look up attached workspace and base image
                    if let Ok(workspaces) = client.list_workspaces(None).await {
                        let attached: Vec<_> = workspaces.iter()
                            .filter(|ws| ws.vm_id.as_deref() == Some(&vm.id))
                            .collect();
                        if !attached.is_empty() {
                            println!();
                            for ws in &attached {
                                let ws_name = ws.name.as_deref().unwrap_or("(unnamed)");
                                let device_type = if ws.is_root_device { "root" } else { "data" };
                                print!("Workspace:  {} ({})", ws_name, device_type);
                                // Resolve base image name
                                if let Some(ref img_id) = ws.master_image_id {
                                    if let Ok(Some(img)) = client.get_image(img_id).await {
                                        print!(" from image \"{}\"", img.name);
                                    }
                                }
                                println!();
                            }
                        }
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
                    println!("{:<20} {:<50}", "NAME", "PATH");
                    for img in &imgs {
                        println!("{:<20} {:<50}", img.name, img.subvolume_path);
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
                    println!("\n  Create a workspace: nexusctl ws create --base {} --name my-ws", img.name);
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
    }
}

async fn cmd_ws(daemon_addr: &str, action: WsAction) -> ExitCode {
    let client = NexusClient::new(daemon_addr);

    match action {
        WsAction::List { base } => {
            match client.list_workspaces(base.as_deref()).await {
                Ok(wss) => {
                    if wss.is_empty() {
                        println!("No workspaces found.");
                        return ExitCode::SUCCESS;
                    }
                    println!("{:<20} {:<50} {:<10}", "NAME", "PATH", "READ-ONLY");
                    for ws in &wss {
                        let name = ws.name.as_deref().unwrap_or("(unnamed)");
                        let ro = if ws.is_read_only { "yes" } else { "no" };
                        println!("{:<20} {:<50} {:<10}", name, ws.subvolume_path, ro);
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
        WsAction::Create { name, base } => {
            let params = CreateWorkspaceParams {
                name: name.clone(),
                base: base.clone(),
            };
            match client.create_workspace(&params).await {
                Ok(ws) => {
                    let ws_name = ws.name.as_deref().unwrap_or(&ws.id);
                    println!("Created workspace \"{}\" from base \"{}\"", ws_name, base);
                    println!("  Path: {}", ws.subvolume_path);
                    println!("\n  Inspect it: nexusctl ws inspect {}", ws_name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot create workspace\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        WsAction::Inspect { name } => {
            match client.get_workspace(&name).await {
                Ok(Some(ws)) => {
                    let ws_name = ws.name.as_deref().unwrap_or("(unnamed)");
                    println!("Name:       {}", ws_name);
                    println!("ID:         {}", ws.id);
                    println!("Path:       {}", ws.subvolume_path);
                    if let Some(ref img_id) = ws.master_image_id {
                        println!("Base Image: {}", img_id);
                    }
                    if let Some(ref vm_id) = ws.vm_id {
                        println!("Attached:   VM {}", vm_id);
                    } else {
                        println!("Attached:   (none)");
                    }
                    println!("Read-Only:  {}", if ws.is_read_only { "yes" } else { "no" });
                    println!("Root Dev:   {}", if ws.is_root_device { "yes" } else { "no" });
                    if let Some(size) = ws.size_bytes {
                        println!("Size:       {} bytes", size);
                    }
                    println!("Created:    {}", format_timestamp(ws.created_at));
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("Error: workspace \"{}\" not found", name);
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
        WsAction::Delete { name, yes } => {
            if !yes {
                eprintln!(
                    "Error: refusing to delete workspace without confirmation\n  \
                     Run with --yes to skip confirmation: nexusctl ws delete {} --yes",
                    name
                );
                return ExitCode::from(EXIT_GENERAL_ERROR);
            }
            match client.delete_workspace(&name).await {
                Ok(true) => {
                    println!("Deleted workspace \"{}\"", name);
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("Error: workspace \"{}\" not found", name);
                    ExitCode::from(EXIT_NOT_FOUND)
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot delete workspace \"{}\"\n  {e}", name);
                    ExitCode::from(EXIT_CONFLICT)
                }
            }
        }
        WsAction::Attach { name, vm, root } => {
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

            match client.attach_workspace(&name, &vm_id, root).await {
                Ok(ws) => {
                    let ws_name = ws.name.as_deref().unwrap_or(&ws.id);
                    println!("Attached workspace \"{}\" to VM \"{}\"", ws_name, vm);
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
                    eprintln!("Error: cannot attach workspace \"{name}\"\n  {e}");
                    ExitCode::from(EXIT_GENERAL_ERROR)
                }
            }
        }
        WsAction::Detach { name } => {
            match client.detach_workspace(&name).await {
                Ok(ws) => {
                    let ws_name = ws.name.as_deref().unwrap_or(&ws.id);
                    println!("Detached workspace \"{}\"", ws_name);
                    ExitCode::SUCCESS
                }
                Err(e) if e.is_connect() => {
                    print_connect_error(daemon_addr);
                    ExitCode::from(EXIT_DAEMON_UNREACHABLE)
                }
                Err(e) => {
                    eprintln!("Error: cannot detach workspace \"{name}\"\n  {e}");
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
                    println!("Build triggered (ID: {})", &build.id[..8]);
                    println!("  Template: {} (version {})", build.name, build.template_version);
                    println!("  Status:   {}", build.status);
                    println!("\n  Check progress: nexusctl build inspect {}", build.id);
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
                        let short_id = &build.id[..std::cmp::min(8, build.id.len())];
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
