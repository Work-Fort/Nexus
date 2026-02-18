/// Schema version — increment when the schema changes.
/// Pre-alpha migration strategy: if the stored version doesn't match,
/// delete the DB and recreate.
pub const SCHEMA_VERSION: u32 = 1;

/// Initial database schema. Executed as a single batch on first start.
/// Domain tables are added by later steps — each step bumps SCHEMA_VERSION
/// and appends its tables here. Pre-alpha migration (delete + recreate)
/// means all tables are always created from this single constant.
pub const SCHEMA_SQL: &str = r#"
-- Schema version tracking
CREATE TABLE schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO schema_meta (key, value) VALUES ('version', '1');

-- Application settings (key-value store)
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('string', 'int', 'bool', 'json'))
);
"#;
