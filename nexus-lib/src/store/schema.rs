/// Schema version — increment when the schema changes.
/// Pre-alpha migration strategy: if the stored version doesn't match,
/// delete the DB and recreate.
pub const SCHEMA_VERSION: u32 = 3;

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
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('portal', 'work', 'service')),
    state TEXT NOT NULL CHECK(state IN ('created', 'running', 'stopped', 'crashed', 'failed')),
    cid INTEGER NOT NULL UNIQUE,
    vcpu_count INTEGER NOT NULL DEFAULT 1,
    mem_size_mib INTEGER NOT NULL DEFAULT 128,
    config_json TEXT,
    pid INTEGER,
    socket_path TEXT,
    uds_path TEXT,
    console_log_path TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    started_at INTEGER,
    stopped_at INTEGER
);

CREATE INDEX idx_vms_role ON vms(role);
CREATE INDEX idx_vms_state ON vms(state);

-- Master images: read-only btrfs subvolumes
CREATE TABLE master_images (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    subvolume_path TEXT NOT NULL UNIQUE,
    size_bytes INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Workspaces: btrfs subvolume snapshots
CREATE TABLE workspaces (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    vm_id TEXT,
    subvolume_path TEXT NOT NULL UNIQUE,
    master_image_id TEXT,
    parent_workspace_id TEXT,
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
"#;
