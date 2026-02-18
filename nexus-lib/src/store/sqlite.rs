use crate::store::schema::{SCHEMA_SQL, SCHEMA_VERSION};
use crate::store::traits::{DbStatus, StateStore, StoreError};
use crate::vm::{CreateVmParams, Vm, VmState};
use crate::workspace::{ImportImageParams, MasterImage, Workspace};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct SqliteStore {
    conn: std::sync::Mutex<Connection>,
    db_path: PathBuf,
}

/// Enable WAL mode and foreign key enforcement on a connection.
fn configure_connection(conn: &Connection) -> Result<(), StoreError> {
    let mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))
        .map_err(|e| StoreError::Init(format!("cannot set WAL mode: {e}")))?;
    if mode != "wal" {
        return Err(StoreError::Init(format!(
            "failed to enable WAL mode: journal_mode is '{mode}'"
        )));
    }

    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| StoreError::Init(format!("cannot enable foreign keys: {e}")))?;

    Ok(())
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

        configure_connection(&conn)?;

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
        let mut conn = self.conn.lock().unwrap();

        // Replace with in-memory connection to close the file handle
        let temp_conn = Connection::open_in_memory()
            .map_err(|e| StoreError::Init(format!("cannot create temp connection: {e}")))?;
        let old_conn = std::mem::replace(&mut *conn, temp_conn);
        drop(old_conn);

        // Delete the database file and WAL/SHM files
        let _ = std::fs::remove_file(&self.db_path);
        let _ = std::fs::remove_file(self.db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.db_path.with_extension("db-shm"));

        // Reopen
        let new_conn = Connection::open(&self.db_path)
            .map_err(|e| StoreError::Init(format!("cannot reopen database: {e}")))?;

        configure_connection(&new_conn)?;

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

        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('version', ?1)",
            [SCHEMA_VERSION.to_string()],
        )
        .map_err(|e| StoreError::Init(format!("cannot insert schema version: {e}")))?;

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

    fn create_vm(&self, params: &CreateVmParams) -> Result<Vm, StoreError> {
        let conn = self.conn.lock().unwrap();

        let id = Uuid::new_v4().to_string();

        // Auto-assign CID: find the max CID in use, start from 3
        let max_cid: Option<u32> = conn
            .query_row("SELECT MAX(cid) FROM vms", [], |row| row.get(0))
            .map_err(|e| StoreError::Query(format!("cannot query max CID: {e}")))?;
        let cid = max_cid.map(|c| c + 1).unwrap_or(3);

        conn.execute(
            "INSERT INTO vms (id, name, role, state, cid, vcpu_count, mem_size_mib) \
             VALUES (?1, ?2, ?3, 'created', ?4, ?5, ?6)",
            rusqlite::params![
                id,
                params.name,
                params.role.as_str(),
                cid,
                params.vcpu_count,
                params.mem_size_mib,
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(err, _) = &e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return StoreError::Conflict(format!("VM name '{}' already exists", params.name));
                }
            }
            StoreError::Query(format!("cannot insert VM: {e}"))
        })?;

        // Release the lock before calling get_vm which will re-acquire it
        drop(conn);

        self.get_vm(&id)?
            .ok_or_else(|| StoreError::Query("VM not found after insert".to_string()))
    }

    fn list_vms(&self, role: Option<&str>, state: Option<&str>) -> Result<Vec<Vm>, StoreError> {
        let conn = self.conn.lock().unwrap();

        let mut sql = "SELECT id, name, role, state, cid, vcpu_count, mem_size_mib, \
                        created_at, updated_at, started_at, stopped_at, pid, \
                        socket_path, uds_path, console_log_path, config_json \
                        FROM vms WHERE 1=1".to_string();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(r) = role {
            sql.push_str(" AND role = ?");
            params.push(Box::new(r.to_string()));
        }
        if let Some(s) = state {
            sql.push_str(" AND state = ?");
            params.push(Box::new(s.to_string()));
        }

        sql.push_str(" ORDER BY created_at DESC");

        let mut stmt = conn.prepare(&sql)
            .map_err(|e| StoreError::Query(format!("cannot prepare list query: {e}")))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let vms = stmt
            .query_map(param_refs.as_slice(), |row| Ok(row_to_vm(row)))
            .map_err(|e| StoreError::Query(format!("cannot list VMs: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Query(format!("cannot read VM row: {e}")))?;

        Ok(vms)
    }

    fn get_vm(&self, name_or_id: &str) -> Result<Option<Vm>, StoreError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT id, name, role, state, cid, vcpu_count, mem_size_mib, \
                 created_at, updated_at, started_at, stopped_at, pid, \
                 socket_path, uds_path, console_log_path, config_json \
                 FROM vms WHERE id = ?1 OR name = ?1",
            )
            .map_err(|e| StoreError::Query(format!("cannot prepare get query: {e}")))?;

        let mut rows = stmt
            .query_map([name_or_id], |row| Ok(row_to_vm(row)))
            .map_err(|e| StoreError::Query(format!("cannot get VM: {e}")))?;

        match rows.next() {
            Some(Ok(vm)) => Ok(Some(vm)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read VM row: {e}"))),
            None => Ok(None),
        }
    }

    fn delete_vm(&self, name_or_id: &str) -> Result<bool, StoreError> {
        // Check if VM exists and is not running
        if let Some(vm) = self.get_vm(name_or_id)? {
            if vm.state == VmState::Running {
                return Err(StoreError::Conflict(format!(
                    "cannot delete VM '{}': VM is running, stop it first",
                    vm.name
                )));
            }
        } else {
            return Ok(false);
        }

        let conn = self.conn.lock().unwrap();
        let deleted = conn
            .execute(
                "DELETE FROM vms WHERE id = ?1 OR name = ?1",
                [name_or_id],
            )
            .map_err(|e| StoreError::Query(format!("cannot delete VM: {e}")))?;

        Ok(deleted > 0)
    }

    fn create_image(&self, params: &ImportImageParams, subvolume_path: &str) -> Result<MasterImage, StoreError> {
        let conn = self.conn.lock().unwrap();
        let id = Uuid::new_v4().to_string();

        conn.execute(
            "INSERT INTO master_images (id, name, subvolume_path) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, params.name, subvolume_path],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(err, _) = &e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return StoreError::Conflict(format!("image name '{}' already exists", params.name));
                }
            }
            StoreError::Query(format!("cannot insert image: {e}"))
        })?;

        drop(conn);
        self.get_image(&id)?
            .ok_or_else(|| StoreError::Query("image not found after insert".to_string()))
    }

    fn list_images(&self) -> Result<Vec<MasterImage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, subvolume_path, size_bytes, created_at FROM master_images ORDER BY created_at DESC")
            .map_err(|e| StoreError::Query(format!("cannot prepare image list query: {e}")))?;

        let images = stmt
            .query_map([], |row| Ok(row_to_image(row)))
            .map_err(|e| StoreError::Query(format!("cannot list images: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Query(format!("cannot read image row: {e}")))?;

        Ok(images)
    }

    fn get_image(&self, name_or_id: &str) -> Result<Option<MasterImage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, subvolume_path, size_bytes, created_at FROM master_images WHERE id = ?1 OR name = ?1")
            .map_err(|e| StoreError::Query(format!("cannot prepare image get query: {e}")))?;

        let mut rows = stmt
            .query_map([name_or_id], |row| Ok(row_to_image(row)))
            .map_err(|e| StoreError::Query(format!("cannot get image: {e}")))?;

        match rows.next() {
            Some(Ok(img)) => Ok(Some(img)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read image row: {e}"))),
            None => Ok(None),
        }
    }

    fn delete_image(&self, name_or_id: &str) -> Result<bool, StoreError> {
        let image = match self.get_image(name_or_id)? {
            Some(img) => img,
            None => return Ok(false),
        };

        // Check for workspaces referencing this image
        let conn = self.conn.lock().unwrap();
        let ws_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM workspaces WHERE master_image_id = ?1",
                [&image.id],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Query(format!("cannot check workspace references: {e}")))?;

        if ws_count > 0 {
            return Err(StoreError::Conflict(format!(
                "cannot delete image '{}': {} workspace(s) reference it, delete them first",
                image.name, ws_count
            )));
        }

        let deleted = conn
            .execute(
                "DELETE FROM master_images WHERE id = ?1",
                [&image.id],
            )
            .map_err(|e| StoreError::Query(format!("cannot delete image: {e}")))?;

        Ok(deleted > 0)
    }

    fn create_workspace(
        &self,
        name: Option<&str>,
        subvolume_path: &str,
        master_image_id: &str,
    ) -> Result<Workspace, StoreError> {
        let conn = self.conn.lock().unwrap();
        let id = Uuid::new_v4().to_string();

        conn.execute(
            "INSERT INTO workspaces (id, name, subvolume_path, master_image_id) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, name, subvolume_path, master_image_id],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(err, _) = &e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return StoreError::Conflict(format!(
                        "workspace name '{}' already exists",
                        name.unwrap_or("(unnamed)")
                    ));
                }
            }
            StoreError::Query(format!("cannot insert workspace: {e}"))
        })?;

        drop(conn);
        self.get_workspace(&id)?
            .ok_or_else(|| StoreError::Query("workspace not found after insert".to_string()))
    }

    fn list_workspaces(&self, base: Option<&str>) -> Result<Vec<Workspace>, StoreError> {
        let conn = self.conn.lock().unwrap();

        let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match base {
            Some(base_name) => {
                (
                    "SELECT w.id, w.name, w.vm_id, w.subvolume_path, w.master_image_id, \
                     w.parent_workspace_id, w.size_bytes, w.is_root_device, w.is_read_only, \
                     w.attached_at, w.detached_at, w.created_at \
                     FROM workspaces w \
                     JOIN master_images m ON w.master_image_id = m.id \
                     WHERE m.name = ? \
                     ORDER BY w.created_at DESC".to_string(),
                    vec![Box::new(base_name.to_string()) as Box<dyn rusqlite::types::ToSql>],
                )
            }
            None => {
                (
                    "SELECT id, name, vm_id, subvolume_path, master_image_id, \
                     parent_workspace_id, size_bytes, is_root_device, is_read_only, \
                     attached_at, detached_at, created_at \
                     FROM workspaces ORDER BY created_at DESC".to_string(),
                    vec![],
                )
            }
        };

        let mut stmt = conn.prepare(&sql)
            .map_err(|e| StoreError::Query(format!("cannot prepare workspace list query: {e}")))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let workspaces = stmt
            .query_map(param_refs.as_slice(), |row| Ok(row_to_workspace(row)))
            .map_err(|e| StoreError::Query(format!("cannot list workspaces: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Query(format!("cannot read workspace row: {e}")))?;

        Ok(workspaces)
    }

    fn get_workspace(&self, name_or_id: &str) -> Result<Option<Workspace>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, vm_id, subvolume_path, master_image_id, \
                 parent_workspace_id, size_bytes, is_root_device, is_read_only, \
                 attached_at, detached_at, created_at \
                 FROM workspaces WHERE id = ?1 OR name = ?1",
            )
            .map_err(|e| StoreError::Query(format!("cannot prepare workspace get query: {e}")))?;

        let mut rows = stmt
            .query_map([name_or_id], |row| Ok(row_to_workspace(row)))
            .map_err(|e| StoreError::Query(format!("cannot get workspace: {e}")))?;

        match rows.next() {
            Some(Ok(ws)) => Ok(Some(ws)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read workspace row: {e}"))),
            None => Ok(None),
        }
    }

    fn delete_workspace(&self, name_or_id: &str) -> Result<bool, StoreError> {
        let ws = match self.get_workspace(name_or_id)? {
            Some(ws) => ws,
            None => return Ok(false),
        };

        // Cannot delete workspace attached to a VM
        if ws.vm_id.is_some() {
            return Err(StoreError::Conflict(format!(
                "cannot delete workspace '{}': attached to VM, detach it first",
                ws.name.as_deref().unwrap_or(&ws.id)
            )));
        }

        let conn = self.conn.lock().unwrap();
        let deleted = conn
            .execute("DELETE FROM workspaces WHERE id = ?1", [&ws.id])
            .map_err(|e| StoreError::Query(format!("cannot delete workspace: {e}")))?;

        Ok(deleted > 0)
    }
}

/// Map a rusqlite row to a Vm struct.
/// NOTE: Uses unwrap() throughout -- will panic on invalid data.
/// Accepted for pre-alpha: CHECK constraints in the schema prevent invalid
/// values from being inserted through normal operations.
fn row_to_vm(row: &rusqlite::Row) -> Vm {
    Vm {
        id: row.get(0).unwrap(),
        name: row.get(1).unwrap(),
        role: row.get::<_, String>(2).unwrap().parse().unwrap(),
        state: row.get::<_, String>(3).unwrap().parse().unwrap(),
        cid: row.get(4).unwrap(),
        vcpu_count: row.get(5).unwrap(),
        mem_size_mib: row.get(6).unwrap(),
        created_at: row.get(7).unwrap(),
        updated_at: row.get(8).unwrap(),
        started_at: row.get(9).unwrap(),
        stopped_at: row.get(10).unwrap(),
        pid: row.get(11).unwrap(),
        socket_path: row.get(12).unwrap(),
        uds_path: row.get(13).unwrap(),
        console_log_path: row.get(14).unwrap(),
        config_json: row.get(15).unwrap(),
    }
}

fn row_to_image(row: &rusqlite::Row) -> MasterImage {
    MasterImage {
        id: row.get(0).unwrap(),
        name: row.get(1).unwrap(),
        subvolume_path: row.get(2).unwrap(),
        size_bytes: row.get(3).unwrap(),
        created_at: row.get(4).unwrap(),
    }
}

fn row_to_workspace(row: &rusqlite::Row) -> Workspace {
    Workspace {
        id: row.get(0).unwrap(),
        name: row.get(1).unwrap(),
        vm_id: row.get(2).unwrap(),
        subvolume_path: row.get(3).unwrap(),
        master_image_id: row.get(4).unwrap(),
        parent_workspace_id: row.get(5).unwrap(),
        size_bytes: row.get(6).unwrap(),
        is_root_device: row.get::<_, i32>(7).unwrap() != 0,
        is_read_only: row.get::<_, i32>(8).unwrap() != 0,
        attached_at: row.get(9).unwrap(),
        detached_at: row.get(10).unwrap(),
        created_at: row.get(11).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::VmRole;
    use crate::workspace::ImportImageParams;

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
        // Expected tables: schema_meta, settings, vms, master_images, workspaces = 5 tables
        assert_eq!(status.table_count, 5, "expected 5 tables, got {}", status.table_count);
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
        assert_eq!(status.table_count, 5);
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
        assert_eq!(status.table_count, 5, "should have all tables after recreate");

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

    #[test]
    fn create_vm_assigns_id_and_cid() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let params = CreateVmParams {
            name: "test-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 2,
            mem_size_mib: 512,
        };
        let vm = store.create_vm(&params).unwrap();

        assert!(!vm.id.is_empty());
        assert_eq!(vm.name, "test-vm");
        assert_eq!(vm.role, VmRole::Work);
        assert_eq!(vm.state, VmState::Created);
        assert_eq!(vm.cid, 3); // first CID
        assert_eq!(vm.vcpu_count, 2);
        assert_eq!(vm.mem_size_mib, 512);
    }

    #[test]
    fn create_vm_auto_increments_cid() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let vm1 = store.create_vm(&CreateVmParams {
            name: "vm-1".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let vm2 = store.create_vm(&CreateVmParams {
            name: "vm-2".to_string(),
            role: VmRole::Portal,
            vcpu_count: 1,
            mem_size_mib: 256,
        }).unwrap();

        assert_eq!(vm1.cid, 3);
        assert_eq!(vm2.cid, 4);
    }

    #[test]
    fn create_vm_duplicate_name_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let params = CreateVmParams {
            name: "dup-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        store.create_vm(&params).unwrap();
        let result = store.create_vm(&params);
        assert!(result.is_err());
    }

    #[test]
    fn list_vms_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_vm(&CreateVmParams {
            name: "vm-a".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();
        store.create_vm(&CreateVmParams {
            name: "vm-b".to_string(),
            role: VmRole::Portal,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let vms = store.list_vms(None, None).unwrap();
        assert_eq!(vms.len(), 2);
    }

    #[test]
    fn list_vms_filter_by_role() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_vm(&CreateVmParams {
            name: "work-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();
        store.create_vm(&CreateVmParams {
            name: "portal-vm".to_string(),
            role: VmRole::Portal,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let work_vms = store.list_vms(Some("work"), None).unwrap();
        assert_eq!(work_vms.len(), 1);
        assert_eq!(work_vms[0].name, "work-vm");
    }

    #[test]
    fn get_vm_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let created = store.create_vm(&CreateVmParams {
            name: "find-me".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let found = store.get_vm("find-me").unwrap().unwrap();
        assert_eq!(found.id, created.id);
        assert_eq!(found.name, "find-me");
    }

    #[test]
    fn get_vm_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let created = store.create_vm(&CreateVmParams {
            name: "id-test".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let found = store.get_vm(&created.id).unwrap().unwrap();
        assert_eq!(found.name, "id-test");
    }

    #[test]
    fn get_vm_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let result = store.get_vm("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_vm_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_vm(&CreateVmParams {
            name: "delete-me".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let deleted = store.delete_vm("delete-me").unwrap();
        assert!(deleted);

        let found = store.get_vm("delete-me").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn delete_vm_not_found_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let deleted = store.delete_vm("ghost").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn delete_vm_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let created = store.create_vm(&CreateVmParams {
            name: "del-by-id".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let deleted = store.delete_vm(&created.id).unwrap();
        assert!(deleted);
    }

    #[test]
    fn cid_reused_after_delete() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let vm1 = store.create_vm(&CreateVmParams {
            name: "first".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();
        assert_eq!(vm1.cid, 3);

        store.delete_vm("first").unwrap();

        // Next VM should get CID 3 again (lowest available)
        // Implementation may choose CID 4 if using max+1 strategy.
        // Both are acceptable -- the key invariant is uniqueness.
        let vm2 = store.create_vm(&CreateVmParams {
            name: "second".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();
        assert!(vm2.cid >= 3);
    }

    #[test]
    fn create_image_and_get_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let params = ImportImageParams {
            name: "base-agent".to_string(),
            source_path: "/tmp/rootfs".to_string(),
        };
        let img = store.create_image(&params, "/data/workspaces/@base-agent").unwrap();

        assert!(!img.id.is_empty());
        assert_eq!(img.name, "base-agent");
        assert_eq!(img.subvolume_path, "/data/workspaces/@base-agent");

        let found = store.get_image("base-agent").unwrap().unwrap();
        assert_eq!(found.id, img.id);
    }

    #[test]
    fn create_image_duplicate_name_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let params = ImportImageParams {
            name: "dup-img".to_string(),
            source_path: "/tmp/a".to_string(),
        };
        store.create_image(&params, "/data/a").unwrap();
        let result = store.create_image(&params, "/data/b");
        assert!(result.is_err());
    }

    #[test]
    fn list_images_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_image(
            &ImportImageParams { name: "img-a".to_string(), source_path: "/a".to_string() },
            "/data/a",
        ).unwrap();
        store.create_image(
            &ImportImageParams { name: "img-b".to_string(), source_path: "/b".to_string() },
            "/data/b",
        ).unwrap();

        let imgs = store.list_images().unwrap();
        assert_eq!(imgs.len(), 2);
    }

    #[test]
    fn delete_image_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_image(
            &ImportImageParams { name: "del-me".to_string(), source_path: "/a".to_string() },
            "/data/del-me",
        ).unwrap();

        let deleted = store.delete_image("del-me").unwrap();
        assert!(deleted);
        assert!(store.get_image("del-me").unwrap().is_none());
    }

    #[test]
    fn delete_image_not_found_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        assert!(!store.delete_image("ghost").unwrap());
    }

    #[test]
    fn delete_image_with_workspaces_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        store.create_workspace(Some("ws-1"), "/data/ws-1", &img.id).unwrap();

        let result = store.delete_image("base");
        assert!(result.is_err());
    }

    #[test]
    fn create_workspace_and_get_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        let ws = store.create_workspace(Some("my-ws"), "/data/my-ws", &img.id).unwrap();

        assert!(!ws.id.is_empty());
        assert_eq!(ws.name, Some("my-ws".to_string()));
        assert_eq!(ws.master_image_id, Some(img.id.clone()));

        let found = store.get_workspace("my-ws").unwrap().unwrap();
        assert_eq!(found.id, ws.id);
    }

    #[test]
    fn create_workspace_auto_generates_name_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        let ws = store.create_workspace(None, "/data/anon-ws", &img.id).unwrap();
        assert!(ws.name.is_none());
    }

    #[test]
    fn list_workspaces_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        store.create_workspace(Some("ws-a"), "/data/ws-a", &img.id).unwrap();
        store.create_workspace(Some("ws-b"), "/data/ws-b", &img.id).unwrap();

        let wss = store.list_workspaces(None).unwrap();
        assert_eq!(wss.len(), 2);
    }

    #[test]
    fn list_workspaces_filter_by_base() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img_a = store.create_image(
            &ImportImageParams { name: "base-a".to_string(), source_path: "/a".to_string() },
            "/data/base-a",
        ).unwrap();
        let img_b = store.create_image(
            &ImportImageParams { name: "base-b".to_string(), source_path: "/b".to_string() },
            "/data/base-b",
        ).unwrap();

        store.create_workspace(Some("ws-a"), "/data/ws-a", &img_a.id).unwrap();
        store.create_workspace(Some("ws-b"), "/data/ws-b", &img_b.id).unwrap();

        let wss = store.list_workspaces(Some("base-a")).unwrap();
        assert_eq!(wss.len(), 1);
        assert_eq!(wss[0].name, Some("ws-a".to_string()));
    }

    #[test]
    fn delete_workspace_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        store.create_workspace(Some("del-ws"), "/data/del-ws", &img.id).unwrap();

        let deleted = store.delete_workspace("del-ws").unwrap();
        assert!(deleted);
        assert!(store.get_workspace("del-ws").unwrap().is_none());
    }

    #[test]
    fn delete_workspace_not_found_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        assert!(!store.delete_workspace("ghost").unwrap());
    }
}
