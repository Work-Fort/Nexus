// SPDX-License-Identifier: GPL-2.0-only
/// Schema version — increment when the schema changes.
/// Pre-alpha migration strategy: if the stored version doesn't match,
/// delete the DB and recreate.
pub const SCHEMA_VERSION: u32 = 9;

/// Database schema. Executed as a single batch on first start.
/// Domain tables are added by later steps — each step bumps SCHEMA_VERSION
/// and appends its tables here. Pre-alpha migration (delete + recreate)
/// means all tables are always created from this single constant.
pub const SCHEMA_SQL: &str = r#"
-- Nexus Database Schema v9 (Pre-Alpha)
--
-- Schema v9 changes:
-- - Renamed 'workspaces' table to 'drives'
-- - Renamed 'storage.workspaces' config key to 'storage.drives'
--
-- During pre-alpha, schema changes are applied by:
-- 1. Updating this file
-- 2. Deleting the database file
-- 3. Restarting the daemon (schema recreates automatically)

-- Application settings (key-value store)
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('string', 'int', 'bool', 'json'))
);

-- Tags for organizational categorization
CREATE TABLE tags (
    name TEXT PRIMARY KEY,
    description TEXT,
    color TEXT,
    text_color TEXT
);

-- VMs: Firecracker microVM instances
CREATE TABLE vms (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('portal', 'work', 'service')),
    state TEXT NOT NULL CHECK(state IN ('created', 'running', 'ready', 'stopped', 'crashed', 'failed', 'unreachable')),
    cid INTEGER NOT NULL UNIQUE,
    vcpu_count INTEGER NOT NULL DEFAULT 1,
    mem_size_mib INTEGER NOT NULL DEFAULT 128,
    config_json TEXT,
    pid INTEGER,
    socket_path TEXT,
    uds_path TEXT,
    console_log_path TEXT,
    agent_connected_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    started_at INTEGER,
    stopped_at INTEGER
);

-- Master images: read-only btrfs subvolumes
CREATE TABLE master_images (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    subvolume_path TEXT NOT NULL UNIQUE,
    size_bytes INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Drives: btrfs subvolume snapshots assigned to VMs
CREATE TABLE drives (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    vm_id INTEGER,
    subvolume_path TEXT NOT NULL UNIQUE,
    master_image_id INTEGER,
    parent_drive_id INTEGER,
    size_bytes INTEGER,
    is_root_device INTEGER NOT NULL DEFAULT 0 CHECK(is_root_device IN (0, 1)),
    is_read_only INTEGER NOT NULL DEFAULT 0 CHECK(is_read_only IN (0, 1)),
    attached_at INTEGER,
    detached_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE SET NULL,
    FOREIGN KEY (master_image_id) REFERENCES master_images(id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_drive_id) REFERENCES drives(id) ON DELETE SET NULL
);

-- VM boot history
CREATE TABLE vm_boot_history (
    id INTEGER PRIMARY KEY,
    vm_id INTEGER NOT NULL,
    boot_started_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    boot_stopped_at INTEGER,
    exit_code INTEGER,
    error_message TEXT,
    console_log_path TEXT,
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
);

-- VM state change history
CREATE TABLE vm_state_history (
    id INTEGER PRIMARY KEY,
    vm_id INTEGER NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT,
    transitioned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
);

-- vsock routes
CREATE TABLE routes (
    id INTEGER PRIMARY KEY,
    source_vm_id INTEGER NOT NULL,
    target_vm_id INTEGER NOT NULL,
    source_port INTEGER NOT NULL,
    target_port INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (source_vm_id) REFERENCES vms(id) ON DELETE CASCADE,
    FOREIGN KEY (target_vm_id) REFERENCES vms(id) ON DELETE CASCADE,
    UNIQUE (source_vm_id, source_port)
);

-- vsock services
CREATE TABLE vsock_services (
    id INTEGER PRIMARY KEY,
    vm_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'stopped' CHECK(state IN ('listening', 'stopped')),
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
    UNIQUE (vm_id, port)
);

-- Network bridges
CREATE TABLE bridges (
    name TEXT PRIMARY KEY,
    subnet TEXT NOT NULL,
    gateway TEXT NOT NULL,
    interface TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- VM network configuration
CREATE TABLE vm_network (
    vm_id INTEGER PRIMARY KEY,
    ip_address TEXT NOT NULL,
    bridge_name TEXT NOT NULL,
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
    FOREIGN KEY (bridge_name) REFERENCES bridges(name) ON DELETE RESTRICT
);

-- Firewall rules
CREATE TABLE firewall_rules (
    id INTEGER PRIMARY KEY,
    vm_id INTEGER NOT NULL,
    rule_order INTEGER NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('accept', 'drop', 'reject')),
    protocol TEXT CHECK(protocol IN ('tcp', 'udp', 'icmp', 'all')),
    source_ip TEXT,
    source_port TEXT,
    dest_ip TEXT,
    dest_port TEXT,
    description TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
    UNIQUE (vm_id, rule_order)
);

-- VM tags
CREATE TABLE vm_tags (
    vm_id INTEGER NOT NULL,
    tag_name TEXT NOT NULL,
    PRIMARY KEY (vm_id, tag_name),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_name) REFERENCES tags(name) ON DELETE CASCADE
);

-- Drive tags
CREATE TABLE drive_tags (
    drive_id INTEGER NOT NULL,
    tag_name TEXT NOT NULL,
    PRIMARY KEY (drive_id, tag_name),
    FOREIGN KEY (drive_id) REFERENCES drives(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_name) REFERENCES tags(name) ON DELETE CASCADE
);

-- Templates
CREATE TABLE templates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version INTEGER NOT NULL DEFAULT 1,
    source_type TEXT NOT NULL CHECK(source_type IN ('rootfs')),
    source_identifier TEXT NOT NULL,
    overlays TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Builds
CREATE TABLE builds (
    id INTEGER PRIMARY KEY,
    template_id INTEGER NOT NULL,
    template_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    overlays TEXT,
    status TEXT NOT NULL DEFAULT 'building' CHECK(status IN ('building', 'success', 'failed')),
    build_log_path TEXT,
    master_image_id INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    completed_at INTEGER,
    FOREIGN KEY (template_id) REFERENCES templates(id) ON DELETE CASCADE,
    FOREIGN KEY (master_image_id) REFERENCES master_images(id) ON DELETE SET NULL
);

-- Asset download providers
CREATE TABLE providers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    asset_type TEXT NOT NULL CHECK(asset_type IN ('kernel', 'rootfs', 'firecracker')),
    provider_type TEXT NOT NULL,
    config TEXT NOT NULL,
    pipeline TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Downloaded kernels
CREATE TABLE kernels (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    architecture TEXT NOT NULL,
    path_on_host TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    pgp_verified INTEGER NOT NULL DEFAULT 0 CHECK(pgp_verified IN (0, 1)),
    file_size INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    downloaded_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Downloaded rootfs images
CREATE TABLE rootfs_images (
    id INTEGER PRIMARY KEY,
    distro TEXT NOT NULL DEFAULT 'alpine',
    version TEXT NOT NULL,
    architecture TEXT NOT NULL,
    path_on_host TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    downloaded_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Downloaded Firecracker binaries
CREATE TABLE firecracker_versions (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    architecture TEXT NOT NULL,
    path_on_host TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    downloaded_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Indexes
CREATE INDEX idx_vms_role ON vms(role);
CREATE INDEX idx_vms_state ON vms(state);
CREATE INDEX idx_drives_vm_id ON drives(vm_id);
CREATE INDEX idx_drives_base ON drives(master_image_id);
CREATE INDEX idx_vm_boot_history_vm_id ON vm_boot_history(vm_id);
CREATE INDEX idx_vm_state_history_vm_id ON vm_state_history(vm_id);
CREATE INDEX idx_vsock_services_vm_id ON vsock_services(vm_id);
CREATE INDEX idx_routes_source ON routes(source_vm_id);
CREATE INDEX idx_routes_target ON routes(target_vm_id);
CREATE INDEX idx_firewall_rules_vm_id ON firewall_rules(vm_id);
CREATE INDEX idx_vm_tags_tag ON vm_tags(tag_name);
CREATE INDEX idx_drive_tags_tag ON drive_tags(tag_name);
CREATE INDEX idx_templates_name ON templates(name);
CREATE INDEX idx_builds_template_id ON builds(template_id);
CREATE INDEX idx_builds_status ON builds(status);
CREATE INDEX idx_builds_master_image_id ON builds(master_image_id);
CREATE INDEX idx_providers_asset_type ON providers(asset_type);
CREATE UNIQUE INDEX idx_providers_default ON providers(asset_type) WHERE is_default = 1;
CREATE UNIQUE INDEX idx_kernels_version_arch ON kernels(version, architecture);
CREATE UNIQUE INDEX idx_rootfs_images_distro_version_arch ON rootfs_images(distro, version, architecture);
CREATE UNIQUE INDEX idx_firecracker_version_arch ON firecracker_versions(version, architecture);

-- Partial index: drive can only be attached to one VM at a time
CREATE UNIQUE INDEX idx_drive_current_attachment
    ON drives(vm_id) WHERE vm_id IS NOT NULL AND detached_at IS NULL;

-- Partial index: each VM has only one root device
CREATE UNIQUE INDEX idx_vm_root_device
    ON drives(vm_id) WHERE vm_id IS NOT NULL AND detached_at IS NULL AND is_root_device = 1;
"#;

/// Seed the providers table with default provider configurations.
/// Called after schema creation (idempotent -- skips if providers already exist).
pub fn seed_default_providers(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM providers", [], |r| r.get(0))?;
    if count > 0 {
        return Ok(());
    }

    conn.execute(
        "INSERT INTO providers (id, name, asset_type, provider_type, config, pipeline, is_default) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            1,
            "anvil",
            "kernel",
            "github_release",
            r#"{"repo": "Work-Fort/Anvil"}"#,
            r#"[{"transport": "http", "credentials": {}, "host": "", "encrypted": true}, {"checksum": "SHA256"}, {"verify": "pgp"}, {"decompress": "xz"}, {"checksum": "SHA256"}]"#,
            1,
        ],
    )?;

    conn.execute(
        "INSERT INTO providers (id, name, asset_type, provider_type, config, pipeline, is_default) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            2,
            "alpine",
            "rootfs",
            "alpine_cdn",
            r#"{"cdn_base": "https://dl-cdn.alpinelinux.org"}"#,
            r#"[{"transport": "http", "credentials": {}, "host": "", "encrypted": true}, {"checksum": "SHA256"}, {"verify": "none"}, {"decompress": "none"}]"#,
            1,
        ],
    )?;

    conn.execute(
        "INSERT INTO providers (id, name, asset_type, provider_type, config, pipeline, is_default) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            3,
            "firecracker",
            "firecracker",
            "github_release",
            r#"{"repo": "firecracker-microvm/firecracker"}"#,
            r#"[{"transport": "http", "credentials": {}, "host": "", "encrypted": true}, {"checksum": "SHA256"}, {"verify": "none"}, {"decompress": "none"}]"#,
            1,
        ],
    )?;

    Ok(())
}
