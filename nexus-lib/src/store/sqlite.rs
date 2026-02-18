use crate::store::schema::{SCHEMA_SQL, SCHEMA_VERSION};
use crate::store::traits::{DbStatus, StateStore, StoreError};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

pub struct SqliteStore {
    conn: std::sync::Mutex<Connection>,
    db_path: PathBuf,
}

impl SqliteStore {
    /// Open a SQLite database at the given path.
    /// Creates the parent directory if it doesn't exist.
    /// Does NOT initialize the schema — call `init()` after opening.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StoreError::Init(format!("cannot create directory {}: {e}", parent.display())))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| StoreError::Init(format!("cannot open database {}: {e}", path.display())))?;

        // Enable WAL mode and verify it was applied
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))
            .map_err(|e| StoreError::Init(format!("cannot set WAL mode: {e}")))?;
        if mode != "wal" {
            return Err(StoreError::Init(format!(
                "failed to enable WAL mode: journal_mode is '{mode}'"
            )));
        }

        // Enable foreign key enforcement
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| StoreError::Init(format!("cannot enable foreign keys: {e}")))?;

        Ok(SqliteStore {
            conn: std::sync::Mutex::new(conn),
            db_path: path.to_path_buf(),
        })
    }

    /// Check the stored schema version. Returns None if schema_meta doesn't exist.
    fn stored_version(&self) -> Option<u32> {
        let conn = self.conn.lock().unwrap();
        let result: Result<String, _> = conn.query_row(
            "SELECT value FROM schema_meta WHERE key = 'version'",
            [],
            |row| row.get(0),
        );
        match result {
            Ok(v) => v.parse().ok(),
            Err(_) => None,
        }
    }

    /// Delete the database file and reopen the connection.
    fn recreate(&self) -> Result<(), StoreError> {
        // Lock and drop the current connection
        {
            let mut conn = self.conn.lock().unwrap();
            let temp_conn = Connection::open_in_memory()
                .map_err(|e| StoreError::Init(format!("cannot create temp connection: {e}")))?;
            let old_conn = std::mem::replace(&mut *conn, temp_conn);
            drop(old_conn);
        }

        // Delete the database file and WAL/SHM files
        let _ = std::fs::remove_file(&self.db_path);
        let _ = std::fs::remove_file(self.db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.db_path.with_extension("db-shm"));

        // Reopen
        let new_conn = Connection::open(&self.db_path)
            .map_err(|e| StoreError::Init(format!("cannot reopen database: {e}")))?;

        let mode: String = new_conn
            .pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))
            .map_err(|e| StoreError::Init(format!("cannot set WAL mode: {e}")))?;
        if mode != "wal" {
            return Err(StoreError::Init(format!(
                "failed to enable WAL mode: journal_mode is '{mode}'"
            )));
        }
        new_conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| StoreError::Init(format!("cannot enable foreign keys: {e}")))?;

        let mut conn = self.conn.lock().unwrap();
        *conn = new_conn;
        Ok(())
    }

    /// Count user tables (excludes sqlite_ internal tables).
    fn table_count(&self) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Query(format!("cannot count tables: {e}")))?;
        Ok(count)
    }

    /// Open the database, initialize the schema, and handle pre-alpha migration.
    /// This is the primary entry point for production use.
    pub fn open_and_init(path: &Path) -> Result<Self, StoreError> {
        let store = Self::open(path)?;

        match store.init() {
            Ok(()) => Ok(store),
            Err(StoreError::SchemaMismatch { expected, found }) => {
                tracing::warn!(
                    expected,
                    found,
                    path = %path.display(),
                    "schema version mismatch, recreating database (pre-alpha migration)"
                );
                store.recreate()?;
                store.init()?;
                Ok(store)
            }
            Err(e) => Err(e),
        }
    }
}

impl StateStore for SqliteStore {
    fn init(&self) -> Result<(), StoreError> {
        // Check if schema already exists with correct version
        if let Some(version) = self.stored_version() {
            if version == SCHEMA_VERSION {
                return Ok(());
            }
            // Version mismatch — for pre-alpha, we need to recreate.
            // The mismatch case is handled by open_and_init() which
            // calls recreate() then init() again.
            return Err(StoreError::SchemaMismatch {
                expected: SCHEMA_VERSION,
                found: version,
            });
        }

        // No schema_meta table — fresh database, create schema
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(SCHEMA_SQL)
            .map_err(|e| StoreError::Init(format!("cannot create schema: {e}")))?;

        Ok(())
    }

    fn status(&self) -> Result<DbStatus, StoreError> {
        let table_count = self.table_count()?;

        let size_bytes = std::fs::metadata(&self.db_path)
            .map(|m| m.len())
            .ok();

        Ok(DbStatus {
            path: self.db_path.to_string_lossy().to_string(),
            table_count,
            size_bytes,
        })
    }

    fn close(&self) -> Result<(), StoreError> {
        // rusqlite closes the connection on drop. This method exists
        // for the trait interface — other backends may need explicit cleanup.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_new_database() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();

        assert!(db_path.exists(), "database file should be created");
    }

    #[test]
    fn init_creates_all_tables() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();

        let status = store.status().unwrap();
        // Expected tables: schema_meta, settings = 2 tables
        // Domain tables (vms, workspaces, etc.) are added by later steps.
        assert_eq!(status.table_count, 2, "expected 2 tables, got {}", status.table_count);
    }

    #[test]
    fn init_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();
        // Second init should not fail
        store.init().unwrap();

        let status = store.status().unwrap();
        assert_eq!(status.table_count, 2);
    }

    #[test]
    fn status_reports_correct_path() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();

        let status = store.status().unwrap();
        assert_eq!(status.path, db_path.to_string_lossy());
    }

    #[test]
    fn status_reports_file_size() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();

        let status = store.status().unwrap();
        assert!(status.size_bytes.unwrap() > 0, "database file should have non-zero size");
    }

    #[test]
    fn schema_version_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();

        let conn = store.conn.lock().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());
    }

    #[test]
    fn schema_mismatch_triggers_recreate() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Create database with a fake old version
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO schema_meta (key, value) VALUES ('version', '0');"
            ).unwrap();
        }

        // open_and_init handles mismatch: detects version "0", deletes DB, recreates
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let status = store.status().unwrap();
        assert_eq!(status.table_count, 2, "should have all tables after recreate");

        let conn = store.conn.lock().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());
    }

    #[test]
    fn foreign_keys_are_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();

        let conn = store.conn.lock().unwrap();
        let fk_enabled: i32 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk_enabled, 1, "foreign keys should be enabled");
    }

    #[test]
    fn wal_mode_is_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = SqliteStore::open(&db_path).unwrap();
        store.init().unwrap();

        let conn = store.conn.lock().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal", "WAL mode should be enabled");
    }
}
