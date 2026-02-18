/// Schema version — increment when the schema changes.
/// Pre-alpha migration strategy: if the stored version doesn't match,
/// delete the DB and recreate.
pub const SCHEMA_VERSION: u32 = 2;

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
"#;
