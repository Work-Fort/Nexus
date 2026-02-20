// SPDX-License-Identifier: GPL-2.0-only
/// Schema version — increment when the schema changes.
/// Pre-alpha migration strategy: if the stored version doesn't match,
/// delete the DB and recreate.
pub const SCHEMA_VERSION: u32 = 8;

/// Database schema. Executed as a single batch on first start.
/// Domain tables are added by later steps — each step bumps SCHEMA_VERSION
/// and appends its tables here. Pre-alpha migration (delete + recreate)
/// means all tables are always created from this single constant.
pub const SCHEMA_SQL: &str = r#"
-- Schema version tracking
CREATE TABLE schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Application settings (key-value store)
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('string', 'int', 'bool', 'json'))
);

-- VMs: Firecracker microVM instances
CREATE TABLE vms (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
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

CREATE INDEX idx_vms_role ON vms(role);
CREATE INDEX idx_vms_state ON vms(state);

-- Master images: read-only btrfs subvolumes
CREATE TABLE master_images (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    subvolume_path TEXT NOT NULL UNIQUE,
    size_bytes INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Workspaces: btrfs subvolume snapshots
CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    vm_id INTEGER,
    subvolume_path TEXT NOT NULL UNIQUE,
    master_image_id INTEGER,
    parent_workspace_id INTEGER,
    size_bytes INTEGER,
    is_root_device INTEGER NOT NULL DEFAULT 0 CHECK(is_root_device IN (0, 1)),
    is_read_only INTEGER NOT NULL DEFAULT 0 CHECK(is_read_only IN (0, 1)),
    attached_at INTEGER,
    detached_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE SET NULL,
    FOREIGN KEY (master_image_id) REFERENCES master_images(id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL
);

CREATE INDEX idx_workspaces_vm_id ON workspaces(vm_id);
CREATE INDEX idx_workspaces_base ON workspaces(master_image_id);

-- Asset download providers (configuration + pipeline stages stored as JSON)
CREATE TABLE providers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    asset_type TEXT NOT NULL CHECK(asset_type IN ('kernel', 'rootfs', 'firecracker')),
    provider_type TEXT NOT NULL,  -- 'github_release', 'archive', 'alpine_cdn'
    config TEXT NOT NULL,         -- JSON: {"repo": "Work-Fort/Anvil"} or {"base_url": "..."}
    pipeline TEXT NOT NULL,       -- JSON: pipeline stages array
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX idx_providers_asset_type ON providers(asset_type);
CREATE UNIQUE INDEX idx_providers_default ON providers(asset_type) WHERE is_default = 1;

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

CREATE UNIQUE INDEX idx_kernels_version_arch ON kernels(version, architecture);

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

CREATE UNIQUE INDEX idx_rootfs_images_distro_version_arch ON rootfs_images(distro, version, architecture);

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

CREATE UNIQUE INDEX idx_firecracker_version_arch ON firecracker_versions(version, architecture);

-- Templates: blueprints for building rootfs images
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

CREATE INDEX idx_templates_name ON templates(name);

-- Builds: immutable build attempts from templates
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

CREATE INDEX idx_builds_template_id ON builds(template_id);
CREATE INDEX idx_builds_status ON builds(status);
CREATE INDEX idx_builds_master_image_id ON builds(master_image_id);

-- VM boot history: tracks each boot/shutdown cycle
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

CREATE INDEX idx_vm_boot_history_vm_id ON vm_boot_history(vm_id);

-- VM state history: tracks state transitions
CREATE TABLE vm_state_history (
    id INTEGER PRIMARY KEY,
    vm_id INTEGER NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    reason TEXT,
    transitioned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
);

CREATE INDEX idx_vm_state_history_vm_id ON vm_state_history(vm_id);
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
