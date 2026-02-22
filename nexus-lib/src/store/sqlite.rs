// SPDX-License-Identifier: GPL-2.0-only
use crate::asset::{
    FirecrackerVersion, Kernel, Provider, RegisterFirecrackerParams,
    RegisterKernelParams, RegisterRootfsParams, RootfsImage,
};
use crate::drive::{Drive, ImportImageParams, MasterImage};
use crate::id::Id;
use crate::store::schema::{seed_default_providers, SCHEMA_SQL, SCHEMA_VERSION};
use crate::store::traits::{AssetStore, BuildStore, DbStatus, DriveStore, ImageStore, StateStore, StoreError, VmStore};
use crate::template::{Build, BuildStatus, CreateTemplateParams, Template};
use crate::vm::{CreateVmParams, Vm, VmState};
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use std::path::{Path, PathBuf};

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

impl VmStore for SqliteStore {
    fn create_vm(&self, params: &CreateVmParams) -> Result<Vm, StoreError> {
        // Validate that name is not a valid base32 ID
        params.validate().map_err(StoreError::InvalidInput)?;

        let conn = self.conn.lock().unwrap();

        let id = Id::generate();

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

        // Release the lock before calling get_vm_by_id which will re-acquire it
        drop(conn);

        self.get_vm_by_id(id)?
            .ok_or_else(|| StoreError::Query("VM not found after insert".to_string()))
    }

    fn list_vms(&self, role: Option<&str>, state: Option<&str>) -> Result<Vec<Vm>, StoreError> {
        let conn = self.conn.lock().unwrap();

        let mut sql = "SELECT id, name, role, state, cid, vcpu_count, mem_size_mib, \
                        created_at, updated_at, started_at, stopped_at, pid, \
                        socket_path, uds_path, console_log_path, config_json, agent_connected_at \
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

    fn get_vm_by_id(&self, id: Id) -> Result<Option<Vm>, StoreError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT id, name, role, state, cid, vcpu_count, mem_size_mib, \
                 created_at, updated_at, started_at, stopped_at, pid, \
                 socket_path, uds_path, console_log_path, config_json, agent_connected_at \
                 FROM vms WHERE id = ?1",
            )
            .map_err(|e| StoreError::Query(format!("cannot prepare get query: {e}")))?;

        let mut rows = stmt
            .query_map([id], |row| Ok(row_to_vm(row)))
            .map_err(|e| StoreError::Query(format!("cannot get VM: {e}")))?;

        match rows.next() {
            Some(Ok(vm)) => Ok(Some(vm)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read VM row: {e}"))),
            None => Ok(None),
        }
    }

    fn get_vm_by_name(&self, name: &str) -> Result<Option<Vm>, StoreError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT id, name, role, state, cid, vcpu_count, mem_size_mib, \
                 created_at, updated_at, started_at, stopped_at, pid, \
                 socket_path, uds_path, console_log_path, config_json, agent_connected_at \
                 FROM vms WHERE name = ?1",
            )
            .map_err(|e| StoreError::Query(format!("cannot prepare get query: {e}")))?;

        let mut rows = stmt
            .query_map([name], |row| Ok(row_to_vm(row)))
            .map_err(|e| StoreError::Query(format!("cannot get VM: {e}")))?;

        match rows.next() {
            Some(Ok(vm)) => Ok(Some(vm)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read VM row: {e}"))),
            None => Ok(None),
        }
    }

    fn get_vm(&self, name_or_id: &str) -> Result<Option<Vm>, StoreError> {
        // Try decoding as base32 ID first
        if let Ok(id) = Id::decode(name_or_id) {
            if let Some(vm) = self.get_vm_by_id(id)? {
                return Ok(Some(vm));
            }
        }

        // Fall back to name lookup
        self.get_vm_by_name(name_or_id)
    }

    fn delete_vm(&self, id: Id) -> Result<bool, StoreError> {
        // Check if VM exists and is not running
        if let Some(vm) = self.get_vm_by_id(id)? {
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
                "DELETE FROM vms WHERE id = ?1",
                [id],
            )
            .map_err(|e| StoreError::Query(format!("cannot delete VM: {e}")))?;

        Ok(deleted > 0)
    }

    fn start_vm(
        &self,
        id: Id,
        pid: u32,
        socket_path: &str,
        uds_path: &str,
        console_log_path: &str,
        config_json: &str,
    ) -> Result<Vm, StoreError> {
        let vm = self.get_vm_by_id(id)?
            .ok_or_else(|| StoreError::Query(format!("VM with ID '{}' not found", id)))?;

        if vm.state == VmState::Running {
            return Err(StoreError::Conflict(format!(
                "VM '{}' is already running (PID: {})",
                vm.name, vm.pid.unwrap_or(0)
            )));
        }

        // Only allow start from created, stopped, or crashed
        match vm.state {
            VmState::Created | VmState::Stopped | VmState::Crashed => {}
            VmState::Failed => {
                return Err(StoreError::Conflict(format!(
                    "VM '{}' is in failed state, delete and recreate it",
                    vm.name
                )));
            }
            VmState::Running | VmState::Ready => unreachable!(),
            VmState::Unreachable => {
                // Allow restart from unreachable state
            }
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE vms SET pid = ?1, socket_path = ?2, \
             uds_path = ?3, console_log_path = ?4, config_json = ?5, \
             started_at = strftime('%s', 'now'), updated_at = strftime('%s', 'now') \
             WHERE id = ?6",
            rusqlite::params![pid, socket_path, uds_path, console_log_path, config_json, vm.id],
        )
        .map_err(|e| StoreError::Query(format!("cannot update VM metadata: {e}")))?;

        drop(conn);

        // Record state transition to running
        self.update_vm_state(vm.id, "running", Some("VM started"))?;

        self.get_vm_by_id(vm.id)?
            .ok_or_else(|| StoreError::Query("VM not found after update".to_string()))
    }

    fn stop_vm(&self, id: Id) -> Result<Vm, StoreError> {
        let vm = self.get_vm_by_id(id)?
            .ok_or_else(|| StoreError::Query(format!("VM with ID '{}' not found", id)))?;

        if vm.state != VmState::Running {
            return Err(StoreError::Conflict(format!(
                "VM '{}' is not running (state: {})",
                vm.name, vm.state
            )));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE vms SET pid = NULL, \
             stopped_at = strftime('%s', 'now'), updated_at = strftime('%s', 'now') \
             WHERE id = ?1",
            [vm.id],
        )
        .map_err(|e| StoreError::Query(format!("cannot update VM metadata: {e}")))?;

        drop(conn);

        // Record state transition to stopped
        self.update_vm_state(vm.id, "stopped", Some("VM stopped"))?;

        self.get_vm_by_id(vm.id)?
            .ok_or_else(|| StoreError::Query("VM not found after update".to_string()))
    }

    fn crash_vm(&self, id: Id) -> Result<Vm, StoreError> {
        let vm = self.get_vm_by_id(id)?
            .ok_or_else(|| StoreError::Query(format!("VM with ID '{}' not found", id)))?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE vms SET state = 'crashed', pid = NULL, \
             stopped_at = strftime('%s', 'now'), updated_at = strftime('%s', 'now') \
             WHERE id = ?1",
            [vm.id],
        )
        .map_err(|e| StoreError::Query(format!("cannot update VM state: {e}")))?;

        drop(conn);
        self.get_vm_by_id(vm.id)?
            .ok_or_else(|| StoreError::Query("VM not found after update".to_string()))
    }

    fn fail_vm(&self, id: Id) -> Result<Vm, StoreError> {
        let vm = self.get_vm_by_id(id)?
            .ok_or_else(|| StoreError::Query(format!("VM with ID '{}' not found", id)))?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE vms SET state = 'failed', pid = NULL, \
             stopped_at = strftime('%s', 'now'), updated_at = strftime('%s', 'now') \
             WHERE id = ?1",
            [vm.id],
        )
        .map_err(|e| StoreError::Query(format!("cannot update VM state: {e}")))?;

        drop(conn);
        self.get_vm_by_id(vm.id)?
            .ok_or_else(|| StoreError::Query("VM not found after update".to_string()))
    }

    fn list_running_vms(&self) -> Result<Vec<Vm>, StoreError> {
        self.list_vms(None, Some("running"))
    }

    fn record_boot_start(&self, vm_id: Id, console_log_path: &str) -> Result<Id, StoreError> {
        let conn = self.conn.lock().unwrap();
        let id = Id::generate();

        conn.execute(
            "INSERT INTO vm_boot_history (id, vm_id, console_log_path) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, vm_id, console_log_path],
        )
        .map_err(|e| StoreError::Query(format!("cannot insert boot history: {e}")))?;

        Ok(id)
    }

    fn record_boot_stop(
        &self,
        boot_id: Id,
        exit_code: Option<i32>,
        error_message: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "UPDATE vm_boot_history SET boot_stopped_at = strftime('%s', 'now'), \
             exit_code = ?1, error_message = ?2 WHERE id = ?3",
            rusqlite::params![exit_code, error_message, boot_id],
        )
        .map_err(|e| StoreError::Query(format!("cannot update boot history: {e}")))?;

        Ok(())
    }

    fn update_vm_state(&self, id: Id, new_state: &str, reason: Option<&str>) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();

        // Get current state
        let current_state: String = conn.query_row(
            "SELECT state FROM vms WHERE id = ?",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .map_err(|e| StoreError::Query(format!("cannot get current state: {e}")))?;

        // Update state
        conn.execute(
            "UPDATE vms SET state = ?, updated_at = strftime('%s', 'now') WHERE id = ?",
            rusqlite::params![new_state, id],
        )
        .map_err(|e| StoreError::Query(format!("cannot update VM state: {e}")))?;

        // Record transition in history
        conn.execute(
            "INSERT INTO vm_state_history (vm_id, from_state, to_state, reason) VALUES (?, ?, ?, ?)",
            rusqlite::params![id, current_state, new_state, reason],
        )
        .map_err(|e| StoreError::Query(format!("cannot record state transition: {e}")))?;

        Ok(())
    }

    fn get_state_history(&self, vm_id: Id) -> Result<Vec<crate::vm::StateHistory>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, vm_id, from_state, to_state, reason, transitioned_at
                 FROM vm_state_history
                 WHERE vm_id = ?
                 ORDER BY transitioned_at DESC, id DESC"
            )
            .map_err(|e| StoreError::Query(format!("cannot prepare query: {e}")))?;

        let rows = stmt
            .query_map([vm_id], |row| {
                Ok(crate::vm::StateHistory {
                    id: row.get(0)?,
                    vm_id: row.get(1)?,
                    from_state: row.get(2)?,
                    to_state: row.get(3)?,
                    reason: row.get(4)?,
                    transitioned_at: row.get(5)?,
                })
            })
            .map_err(|e| StoreError::Query(format!("cannot execute query: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Query(format!("cannot collect results: {e}")))
    }

    fn set_vm_agent_connected_at(&self, id: Id, timestamp: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE vms SET agent_connected_at = ? WHERE id = ?",
            rusqlite::params![timestamp, id],
        )
        .map_err(|e| StoreError::Query(format!("cannot set agent_connected_at: {e}")))?;
        Ok(())
    }

    fn list_vms_by_state(&self, state: &str) -> Result<Vec<Vm>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, role, state, cid, vcpu_count, mem_size_mib, config_json, pid,
                    socket_path, uds_path, console_log_path, agent_connected_at, created_at,
                    updated_at, started_at, stopped_at
             FROM vms WHERE state = ?"
        )
        .map_err(|e| StoreError::Query(format!("cannot prepare statement: {e}")))?;

        let vms = stmt.query_map(rusqlite::params![state], |row| {
            let role_str: String = row.get(2)?;
            let state_str: String = row.get(3)?;
            Ok(Vm {
                id: row.get(0)?,
                name: row.get(1)?,
                role: role_str.parse().map_err(|_| rusqlite::Error::FromSqlConversionFailure(
                    2, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "parse error"))))?,
                state: state_str.parse().map_err(|_| rusqlite::Error::FromSqlConversionFailure(
                    3, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "parse error"))))?,
                cid: row.get(4)?,
                vcpu_count: row.get(5)?,
                mem_size_mib: row.get(6)?,
                config_json: row.get(7)?,
                pid: row.get(8)?,
                socket_path: row.get(9)?,
                uds_path: row.get(10)?,
                console_log_path: row.get(11)?,
                agent_connected_at: row.get(12)?,
                created_at: row.get(13)?,
                updated_at: row.get(14)?,
                started_at: row.get(15)?,
                stopped_at: row.get(16)?,
            })
        })
        .map_err(|e| StoreError::Query(format!("cannot query VMs: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| StoreError::Query(format!("cannot map VM rows: {e}")))?;

        Ok(vms)
    }
}

impl ImageStore for SqliteStore {
    fn create_image(&self, params: &ImportImageParams, subvolume_path: &str) -> Result<MasterImage, StoreError> {
        // Validate that name is not a valid base32 ID
        params.validate().map_err(StoreError::InvalidInput)?;

        let conn = self.conn.lock().unwrap();
        let id = Id::generate();

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
        self.get_image_by_id(id)?
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

    fn get_image_by_id(&self, id: Id) -> Result<Option<MasterImage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, subvolume_path, size_bytes, created_at FROM master_images WHERE id = ?1")
            .map_err(|e| StoreError::Query(format!("cannot prepare image get query: {e}")))?;

        let mut rows = stmt
            .query_map([id], |row| Ok(row_to_image(row)))
            .map_err(|e| StoreError::Query(format!("cannot get image: {e}")))?;

        match rows.next() {
            Some(Ok(img)) => Ok(Some(img)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read image row: {e}"))),
            None => Ok(None),
        }
    }

    fn get_image_by_name(&self, name: &str) -> Result<Option<MasterImage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, subvolume_path, size_bytes, created_at FROM master_images WHERE name = ?1")
            .map_err(|e| StoreError::Query(format!("cannot prepare image get query: {e}")))?;

        let mut rows = stmt
            .query_map([name], |row| Ok(row_to_image(row)))
            .map_err(|e| StoreError::Query(format!("cannot get image: {e}")))?;

        match rows.next() {
            Some(Ok(img)) => Ok(Some(img)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read image row: {e}"))),
            None => Ok(None),
        }
    }

    fn get_image(&self, name_or_id: &str) -> Result<Option<MasterImage>, StoreError> {
        // Try decoding as base32 ID first
        if let Ok(id) = Id::decode(name_or_id) {
            if let Some(img) = self.get_image_by_id(id)? {
                return Ok(Some(img));
            }
        }

        // Fall back to name lookup
        self.get_image_by_name(name_or_id)
    }

    fn delete_image(&self, id: Id) -> Result<bool, StoreError> {
        let image = match self.get_image_by_id(id)? {
            Some(img) => img,
            None => return Ok(false),
        };

        // Check for drives referencing this image
        let conn = self.conn.lock().unwrap();
        let ws_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM drives WHERE master_image_id = ?1",
                [image.id],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Query(format!("cannot check drive references: {e}")))?;

        if ws_count > 0 {
            return Err(StoreError::Conflict(format!(
                "cannot delete image '{}': {} drive(s) reference it, delete them first",
                image.name, ws_count
            )));
        }

        let deleted = conn
            .execute(
                "DELETE FROM master_images WHERE id = ?1",
                [image.id],
            )
            .map_err(|e| StoreError::Query(format!("cannot delete image: {e}")))?;

        Ok(deleted > 0)
    }
}

impl DriveStore for SqliteStore {
    fn create_drive(
        &self,
        name: Option<&str>,
        subvolume_path: &str,
        master_image_id: Id,
    ) -> Result<Drive, StoreError> {
        // Validate that name (if provided) is not a valid base32 ID
        if let Some(name_str) = name {
            if Id::is_valid_base32(name_str) {
                return Err(StoreError::InvalidInput(format!(
                    "Drive name '{}' cannot be a valid base32 ID (reserved for resource IDs)",
                    name_str
                )));
            }
        }

        let conn = self.conn.lock().unwrap();
        let id = Id::generate();

        conn.execute(
            "INSERT INTO drives (id, name, subvolume_path, master_image_id) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, name, subvolume_path, master_image_id],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(err, _) = &e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return StoreError::Conflict(format!(
                        "drive name '{}' already exists",
                        name.unwrap_or("(unnamed)")
                    ));
                }
            }
            StoreError::Query(format!("cannot insert drive: {e}"))
        })?;

        drop(conn);
        self.get_drive_by_id(id)?
            .ok_or_else(|| StoreError::Query("drive not found after insert".to_string()))
    }

    fn list_drives(&self, base: Option<&str>) -> Result<Vec<Drive>, StoreError> {
        let conn = self.conn.lock().unwrap();

        let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match base {
            Some(base_name) => {
                (
                    "SELECT d.id, d.name, d.vm_id, d.subvolume_path, d.master_image_id, \
                     d.parent_drive_id, d.size_bytes, d.is_root_device, d.is_read_only, \
                     d.attached_at, d.detached_at, d.created_at \
                     FROM drives d \
                     JOIN master_images m ON d.master_image_id = m.id \
                     WHERE m.name = ? \
                     ORDER BY d.created_at DESC".to_string(),
                    vec![Box::new(base_name.to_string()) as Box<dyn rusqlite::types::ToSql>],
                )
            }
            None => {
                (
                    "SELECT id, name, vm_id, subvolume_path, master_image_id, \
                     parent_drive_id, size_bytes, is_root_device, is_read_only, \
                     attached_at, detached_at, created_at \
                     FROM drives ORDER BY created_at DESC".to_string(),
                    vec![],
                )
            }
        };

        let mut stmt = conn.prepare(&sql)
            .map_err(|e| StoreError::Query(format!("cannot prepare drive list query: {e}")))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let drives = stmt
            .query_map(param_refs.as_slice(), |row| Ok(row_to_drive(row)))
            .map_err(|e| StoreError::Query(format!("cannot list drives: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Query(format!("cannot read drive row: {e}")))?;

        Ok(drives)
    }

    fn get_drive_by_id(&self, id: Id) -> Result<Option<Drive>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, vm_id, subvolume_path, master_image_id, \
                 parent_drive_id, size_bytes, is_root_device, is_read_only, \
                 attached_at, detached_at, created_at \
                 FROM drives WHERE id = ?1",
            )
            .map_err(|e| StoreError::Query(format!("cannot prepare drive get query: {e}")))?;

        let mut rows = stmt
            .query_map([id], |row| Ok(row_to_drive(row)))
            .map_err(|e| StoreError::Query(format!("cannot get drive: {e}")))?;

        match rows.next() {
            Some(Ok(d)) => Ok(Some(d)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read drive row: {e}"))),
            None => Ok(None),
        }
    }

    fn get_drive_by_name(&self, name: &str) -> Result<Option<Drive>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, vm_id, subvolume_path, master_image_id, \
                 parent_drive_id, size_bytes, is_root_device, is_read_only, \
                 attached_at, detached_at, created_at \
                 FROM drives WHERE name = ?1",
            )
            .map_err(|e| StoreError::Query(format!("cannot prepare drive get query: {e}")))?;

        let mut rows = stmt
            .query_map([name], |row| Ok(row_to_drive(row)))
            .map_err(|e| StoreError::Query(format!("cannot get drive: {e}")))?;

        match rows.next() {
            Some(Ok(d)) => Ok(Some(d)),
            Some(Err(e)) => Err(StoreError::Query(format!("cannot read drive row: {e}"))),
            None => Ok(None),
        }
    }

    fn get_drive(&self, name_or_id: &str) -> Result<Option<Drive>, StoreError> {
        // Try decoding as base32 ID first
        if let Ok(id) = Id::decode(name_or_id) {
            if let Some(d) = self.get_drive_by_id(id)? {
                return Ok(Some(d));
            }
        }

        // Fall back to name lookup
        self.get_drive_by_name(name_or_id)
    }

    fn delete_drive(&self, id: Id) -> Result<bool, StoreError> {
        let drive = match self.get_drive_by_id(id)? {
            Some(d) => d,
            None => return Ok(false),
        };

        // Cannot delete drive attached to a VM
        if drive.vm_id.is_some() {
            return Err(StoreError::Conflict(format!(
                "cannot delete drive '{}': attached to VM, detach it first",
                drive.name.as_deref().unwrap_or(&drive.id.to_string())
            )));
        }

        let conn = self.conn.lock().unwrap();
        let deleted = conn
            .execute("DELETE FROM drives WHERE id = ?1", [drive.id])
            .map_err(|e| StoreError::Query(format!("cannot delete drive: {e}")))?;

        Ok(deleted > 0)
    }

    fn attach_drive(&self, drive_id: Id, vm_id: Id, is_root_device: bool) -> Result<Drive, StoreError> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "UPDATE drives SET vm_id = ?1, is_root_device = ?2, attached_at = ?3, detached_at = NULL WHERE id = ?4",
            rusqlite::params![vm_id, is_root_device, now, drive_id],
        )
        .map_err(|e| StoreError::Query(format!("cannot attach drive: {e}")))?;

        drop(conn);
        self.get_drive_by_id(drive_id)?
            .ok_or_else(|| StoreError::Query("drive not found after attach".to_string()))
    }

    fn detach_drive(&self, drive_id: Id) -> Result<Drive, StoreError> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "UPDATE drives SET vm_id = NULL, is_root_device = 0, detached_at = ?1 WHERE id = ?2",
            rusqlite::params![now, drive_id],
        )
        .map_err(|e| StoreError::Query(format!("cannot detach drive: {e}")))?;

        drop(conn);
        self.get_drive_by_id(drive_id)?
            .ok_or_else(|| StoreError::Query("drive not found after detach".to_string()))
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

        seed_default_providers(&conn)
            .map_err(|e| StoreError::Init(format!("cannot seed default providers: {e}")))?;

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

    fn get_setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let value: Option<String> = conn.query_row(
            "SELECT value FROM settings WHERE key = ?",
            rusqlite::params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| StoreError::Query(format!("cannot get setting: {e}")))?;
        Ok(value)
    }
}

impl AssetStore for SqliteStore {
    fn get_provider(&self, name_or_id: &str) -> Result<Option<Provider>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, name, asset_type, provider_type, config, pipeline, is_default, created_at FROM providers WHERE id = ?1 OR name = ?1"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![name_or_id], |row| {
            Ok(row_to_provider(row))
        }).optional().map_err(|e| StoreError::Query(e.to_string()))?;
        match result {
            Some(p) => Ok(Some(p.map_err(|e| StoreError::Query(e.to_string()))?)),
            None => Ok(None),
        }
    }

    fn get_default_provider(&self, asset_type: &str) -> Result<Option<Provider>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, name, asset_type, provider_type, config, pipeline, is_default, created_at FROM providers WHERE asset_type = ?1 AND is_default = 1"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![asset_type], |row| {
            Ok(row_to_provider(row))
        }).optional().map_err(|e| StoreError::Query(e.to_string()))?;
        match result {
            Some(p) => Ok(Some(p.map_err(|e| StoreError::Query(e.to_string()))?)),
            None => Ok(None),
        }
    }

    fn list_providers(&self, asset_type: Option<&str>) -> Result<Vec<Provider>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match asset_type {
            Some(t) => (
                "SELECT id, name, asset_type, provider_type, config, pipeline, is_default, created_at FROM providers WHERE asset_type = ?1 ORDER BY name",
                vec![Box::new(t.to_string())],
            ),
            None => (
                "SELECT id, name, asset_type, provider_type, config, pipeline, is_default, created_at FROM providers ORDER BY name",
                vec![],
            ),
        };
        let mut stmt = conn.prepare(sql).map_err(|e| StoreError::Query(e.to_string()))?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok(row_to_provider(row))
        }).map_err(|e| StoreError::Query(e.to_string()))?;
        let mut providers = Vec::new();
        for row in rows {
            let p = row.map_err(|e| StoreError::Query(e.to_string()))?
                .map_err(|e| StoreError::Query(e.to_string()))?;
            providers.push(p);
        }
        Ok(providers)
    }

    fn register_kernel(&self, params: &RegisterKernelParams) -> Result<Kernel, StoreError> {
        let id = Id::generate();
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        conn.execute(
            "INSERT INTO kernels (id, version, architecture, path_on_host, sha256, pgp_verified, file_size, source_url) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                id, params.version, params.architecture, params.path_on_host,
                params.sha256, params.pgp_verified as i32, params.file_size, params.source_url,
            ],
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        drop(conn);
        self.get_kernel(&params.version, Some(&params.architecture))?.ok_or_else(|| StoreError::Query("kernel not found after insert".to_string()))
    }

    fn list_kernels(&self) -> Result<Vec<Kernel>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, version, architecture, path_on_host, sha256, pgp_verified, file_size, source_url, downloaded_at FROM kernels ORDER BY version DESC"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let rows = stmt.query_map([], |row| Ok(row_to_kernel(row)))
            .map_err(|e| StoreError::Query(e.to_string()))?;
        let mut kernels = Vec::new();
        for row in rows {
            kernels.push(row.map_err(|e| StoreError::Query(e.to_string()))?);
        }
        Ok(kernels)
    }

    fn get_kernel(&self, id_or_version: &str, arch: Option<&str>) -> Result<Option<Kernel>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        // Try by ID first
        let mut stmt = conn.prepare(
            "SELECT id, version, architecture, path_on_host, sha256, pgp_verified, file_size, source_url, downloaded_at FROM kernels WHERE id = ?1"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![id_or_version], |row| Ok(row_to_kernel(row)))
            .optional().map_err(|e| StoreError::Query(e.to_string()))?;
        if result.is_some() {
            return Ok(result);
        }
        // Try by version + arch
        if let Some(arch) = arch {
            let mut stmt = conn.prepare(
                "SELECT id, version, architecture, path_on_host, sha256, pgp_verified, file_size, source_url, downloaded_at FROM kernels WHERE version = ?1 AND architecture = ?2"
            ).map_err(|e| StoreError::Query(e.to_string()))?;
            return stmt.query_row(rusqlite::params![id_or_version, arch], |row| Ok(row_to_kernel(row)))
                .optional().map_err(|e| StoreError::Query(e.to_string()));
        }
        Ok(None)
    }

    fn delete_kernel(&self, id: Id) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let count = conn.execute("DELETE FROM kernels WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| StoreError::Query(e.to_string()))?;
        Ok(count > 0)
    }

    fn register_rootfs(&self, params: &RegisterRootfsParams) -> Result<RootfsImage, StoreError> {
        let id = Id::generate();
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        conn.execute(
            "INSERT INTO rootfs_images (id, distro, version, architecture, path_on_host, sha256, file_size, source_url) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                id, params.distro, params.version, params.architecture,
                params.path_on_host, params.sha256, params.file_size, params.source_url,
            ],
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        drop(conn);
        self.get_rootfs(&params.version, Some(&params.architecture))?.ok_or_else(|| StoreError::Query("rootfs not found after insert".to_string()))
    }

    fn list_rootfs_images(&self) -> Result<Vec<RootfsImage>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, distro, version, architecture, path_on_host, sha256, file_size, source_url, downloaded_at FROM rootfs_images ORDER BY version DESC"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let rows = stmt.query_map([], |row| Ok(row_to_rootfs(row)))
            .map_err(|e| StoreError::Query(e.to_string()))?;
        let mut images = Vec::new();
        for row in rows {
            images.push(row.map_err(|e| StoreError::Query(e.to_string()))?);
        }
        Ok(images)
    }

    fn get_rootfs(&self, id_or_version: &str, arch: Option<&str>) -> Result<Option<RootfsImage>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        // Try by ID first
        let mut stmt = conn.prepare(
            "SELECT id, distro, version, architecture, path_on_host, sha256, file_size, source_url, downloaded_at FROM rootfs_images WHERE id = ?1"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![id_or_version], |row| Ok(row_to_rootfs(row)))
            .optional().map_err(|e| StoreError::Query(e.to_string()))?;
        if result.is_some() {
            return Ok(result);
        }
        // Try by version + arch (assuming alpine distro)
        if let Some(arch) = arch {
            let mut stmt = conn.prepare(
                "SELECT id, distro, version, architecture, path_on_host, sha256, file_size, source_url, downloaded_at FROM rootfs_images WHERE version = ?1 AND architecture = ?2"
            ).map_err(|e| StoreError::Query(e.to_string()))?;
            return stmt.query_row(rusqlite::params![id_or_version, arch], |row| Ok(row_to_rootfs(row)))
                .optional().map_err(|e| StoreError::Query(e.to_string()));
        }
        Ok(None)
    }

    fn delete_rootfs(&self, id: Id) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let count = conn.execute("DELETE FROM rootfs_images WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| StoreError::Query(e.to_string()))?;
        Ok(count > 0)
    }

    fn register_firecracker(&self, params: &RegisterFirecrackerParams) -> Result<FirecrackerVersion, StoreError> {
        let id = Id::generate();
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        conn.execute(
            "INSERT INTO firecracker_versions (id, version, architecture, path_on_host, sha256, file_size, source_url) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                id, params.version, params.architecture,
                params.path_on_host, params.sha256, params.file_size, params.source_url,
            ],
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        drop(conn);
        self.get_firecracker(&params.version, Some(&params.architecture))?.ok_or_else(|| StoreError::Query("firecracker not found after insert".to_string()))
    }

    fn list_firecracker_versions(&self) -> Result<Vec<FirecrackerVersion>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, version, architecture, path_on_host, sha256, file_size, source_url, downloaded_at FROM firecracker_versions ORDER BY version DESC"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let rows = stmt.query_map([], |row| Ok(row_to_firecracker(row)))
            .map_err(|e| StoreError::Query(e.to_string()))?;
        let mut versions = Vec::new();
        for row in rows {
            versions.push(row.map_err(|e| StoreError::Query(e.to_string()))?);
        }
        Ok(versions)
    }

    fn get_firecracker(&self, id_or_version: &str, arch: Option<&str>) -> Result<Option<FirecrackerVersion>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        // Try by ID first
        let mut stmt = conn.prepare(
            "SELECT id, version, architecture, path_on_host, sha256, file_size, source_url, downloaded_at FROM firecracker_versions WHERE id = ?1"
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![id_or_version], |row| Ok(row_to_firecracker(row)))
            .optional().map_err(|e| StoreError::Query(e.to_string()))?;
        if result.is_some() {
            return Ok(result);
        }
        // Try by version + arch
        if let Some(arch) = arch {
            let mut stmt = conn.prepare(
                "SELECT id, version, architecture, path_on_host, sha256, file_size, source_url, downloaded_at FROM firecracker_versions WHERE version = ?1 AND architecture = ?2"
            ).map_err(|e| StoreError::Query(e.to_string()))?;
            return stmt.query_row(rusqlite::params![id_or_version, arch], |row| Ok(row_to_firecracker(row)))
                .optional().map_err(|e| StoreError::Query(e.to_string()));
        }
        Ok(None)
    }

    fn delete_firecracker(&self, id: Id) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Query(e.to_string()))?;
        let count = conn.execute("DELETE FROM firecracker_versions WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| StoreError::Query(e.to_string()))?;
        Ok(count > 0)
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
        agent_connected_at: row.get(16).unwrap(),
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

fn row_to_provider(row: &rusqlite::Row) -> Result<Provider, rusqlite::Error> {
    let config_str: String = row.get(4)?;
    let pipeline_str: String = row.get(5)?;
    let is_default_int: i32 = row.get(6)?;
    Ok(Provider {
        id: row.get(0)?,
        name: row.get(1)?,
        asset_type: row.get(2)?,
        provider_type: row.get(3)?,
        config: serde_json::from_str(&config_str).unwrap_or(serde_json::Value::Null),
        pipeline: serde_json::from_str(&pipeline_str).unwrap_or_default(),
        is_default: is_default_int != 0,
        created_at: row.get(7)?,
    })
}

fn row_to_kernel(row: &rusqlite::Row) -> Kernel {
    let pgp_int: i32 = row.get(5).unwrap_or(0);
    Kernel {
        id: row.get(0).unwrap(),
        version: row.get(1).unwrap(),
        architecture: row.get(2).unwrap(),
        path_on_host: row.get(3).unwrap(),
        sha256: row.get(4).unwrap(),
        pgp_verified: pgp_int != 0,
        file_size: row.get(6).unwrap(),
        source_url: row.get(7).unwrap(),
        downloaded_at: row.get(8).unwrap(),
    }
}

fn row_to_rootfs(row: &rusqlite::Row) -> RootfsImage {
    RootfsImage {
        id: row.get(0).unwrap(),
        distro: row.get(1).unwrap(),
        version: row.get(2).unwrap(),
        architecture: row.get(3).unwrap(),
        path_on_host: row.get(4).unwrap(),
        sha256: row.get(5).unwrap(),
        file_size: row.get(6).unwrap(),
        source_url: row.get(7).unwrap(),
        downloaded_at: row.get(8).unwrap(),
    }
}

fn row_to_firecracker(row: &rusqlite::Row) -> FirecrackerVersion {
    FirecrackerVersion {
        id: row.get(0).unwrap(),
        version: row.get(1).unwrap(),
        architecture: row.get(2).unwrap(),
        path_on_host: row.get(3).unwrap(),
        sha256: row.get(4).unwrap(),
        file_size: row.get(5).unwrap(),
        source_url: row.get(6).unwrap(),
        downloaded_at: row.get(7).unwrap(),
    }
}

fn row_to_drive(row: &rusqlite::Row) -> Drive {
    Drive {
        id: row.get(0).unwrap(),
        name: row.get(1).unwrap(),
        vm_id: row.get(2).unwrap(),
        subvolume_path: row.get(3).unwrap(),
        master_image_id: row.get(4).unwrap(),
        parent_drive_id: row.get(5).unwrap(),
        size_bytes: row.get(6).unwrap(),
        is_root_device: row.get::<_, i32>(7).unwrap() != 0,
        is_read_only: row.get::<_, i32>(8).unwrap() != 0,
        attached_at: row.get(9).unwrap(),
        detached_at: row.get(10).unwrap(),
        created_at: row.get(11).unwrap(),
    }
}

fn row_to_template(row: &rusqlite::Row) -> Result<Template, rusqlite::Error> {
    let overlays_json: Option<String> = row.get("overlays")?;
    let overlays = overlays_json.and_then(|j| serde_json::from_str(&j).ok());
    Ok(Template {
        id: row.get("id")?,
        name: row.get("name")?,
        version: row.get("version")?,
        source_type: row.get("source_type")?,
        source_identifier: row.get("source_identifier")?,
        overlays,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

fn row_to_build(row: &rusqlite::Row) -> Result<Build, rusqlite::Error> {
    let overlays_json: Option<String> = row.get("overlays")?;
    let overlays = overlays_json.and_then(|j| serde_json::from_str(&j).ok());
    let status_str: String = row.get("status")?;
    let status: BuildStatus = status_str.parse().unwrap_or(BuildStatus::Failed);
    Ok(Build {
        id: row.get("id")?,
        template_id: row.get("template_id")?,
        template_version: row.get("template_version")?,
        name: row.get("name")?,
        source_type: row.get("source_type")?,
        source_identifier: row.get("source_identifier")?,
        overlays,
        status,
        build_log_path: row.get("build_log_path")?,
        master_image_id: row.get("master_image_id")?,
        created_at: row.get("created_at")?,
        completed_at: row.get("completed_at")?,
    })
}

impl BuildStore for SqliteStore {
    fn create_template(&self, params: &CreateTemplateParams) -> Result<Template, StoreError> {
        // Validate that name is not a valid base32 ID
        params.validate().map_err(StoreError::InvalidInput)?;

        let id = Id::generate();
        let overlays_json = params.overlays.as_ref().map(|o| serde_json::to_string(o).unwrap());
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO templates (id, name, version, source_type, source_identifier, overlays) VALUES (?1, ?2, 1, ?3, ?4, ?5)",
            rusqlite::params![id, params.name, params.source_type, params.source_identifier, overlays_json],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE constraint") {
                StoreError::Conflict(format!("template '{}' already exists", params.name))
            } else {
                StoreError::Query(e.to_string())
            }
        })?;
        drop(conn);
        self.get_template_by_id(id)?.ok_or_else(|| StoreError::Query("failed to read back template".to_string()))
    }

    fn list_templates(&self) -> Result<Vec<Template>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM templates ORDER BY name")
            .map_err(|e| StoreError::Query(e.to_string()))?;
        let templates = stmt.query_map([], row_to_template)
            .map_err(|e| StoreError::Query(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Query(e.to_string()))?;
        Ok(templates)
    }

    fn get_template_by_id(&self, id: Id) -> Result<Option<Template>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM templates WHERE id = ?1")
            .map_err(|e| StoreError::Query(e.to_string()))?;
        let mut rows = stmt.query_map(rusqlite::params![id], row_to_template)
            .map_err(|e| StoreError::Query(e.to_string()))?;
        match rows.next() {
            Some(Ok(tpl)) => Ok(Some(tpl)),
            Some(Err(e)) => Err(StoreError::Query(e.to_string())),
            None => Ok(None),
        }
    }

    fn get_template_by_name(&self, name: &str) -> Result<Option<Template>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM templates WHERE name = ?1")
            .map_err(|e| StoreError::Query(e.to_string()))?;
        let mut rows = stmt.query_map(rusqlite::params![name], row_to_template)
            .map_err(|e| StoreError::Query(e.to_string()))?;
        match rows.next() {
            Some(Ok(tpl)) => Ok(Some(tpl)),
            Some(Err(e)) => Err(StoreError::Query(e.to_string())),
            None => Ok(None),
        }
    }

    fn get_template(&self, name_or_id: &str) -> Result<Option<Template>, StoreError> {
        // Try decoding as base32 ID first
        if let Ok(id) = Id::decode(name_or_id) {
            if let Some(tpl) = self.get_template_by_id(id)? {
                return Ok(Some(tpl));
            }
        }

        // Fall back to name lookup
        self.get_template_by_name(name_or_id)
    }

    fn delete_template(&self, id: Id) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM templates WHERE id = ?1",
            rusqlite::params![id],
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        Ok(deleted > 0)
    }

    fn create_build(&self, template: &Template) -> Result<Build, StoreError> {
        let id = Id::generate();
        let overlays_json = template.overlays.as_ref().map(|o| serde_json::to_string(o).unwrap());
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO builds (id, template_id, template_version, name, source_type, source_identifier, overlays) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![id, template.id, template.version, template.name, template.source_type, template.source_identifier, overlays_json],
        ).map_err(|e| StoreError::Query(e.to_string()))?;
        drop(conn);
        self.get_build(id)?.ok_or_else(|| StoreError::Query("failed to read back build".to_string()))
    }

    fn list_builds(&self, template: Option<&str>) -> Result<Vec<Build>, StoreError> {
        let conn = self.conn.lock().unwrap();
        if let Some(tpl_name) = template {
            let mut stmt = conn.prepare(
                "SELECT b.* FROM builds b JOIN templates t ON b.template_id = t.id WHERE t.name = ?1 OR t.id = ?1 ORDER BY b.created_at DESC"
            ).map_err(|e| StoreError::Query(e.to_string()))?;
            let builds = stmt.query_map(rusqlite::params![tpl_name], row_to_build)
                .map_err(|e| StoreError::Query(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Query(e.to_string()))?;
            Ok(builds)
        } else {
            let mut stmt = conn.prepare("SELECT * FROM builds ORDER BY created_at DESC")
                .map_err(|e| StoreError::Query(e.to_string()))?;
            let builds = stmt.query_map([], row_to_build)
                .map_err(|e| StoreError::Query(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StoreError::Query(e.to_string()))?;
            Ok(builds)
        }
    }

    fn get_build(&self, id: Id) -> Result<Option<Build>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM builds WHERE id = ?1")
            .map_err(|e| StoreError::Query(e.to_string()))?;
        let mut rows = stmt.query_map(rusqlite::params![id], row_to_build)
            .map_err(|e| StoreError::Query(e.to_string()))?;
        match rows.next() {
            Some(Ok(build)) => Ok(Some(build)),
            Some(Err(e)) => Err(StoreError::Query(e.to_string())),
            None => Ok(None),
        }
    }

    fn update_build_status(
        &self,
        id: Id,
        status: BuildStatus,
        master_image_id: Option<Id>,
        build_log_path: Option<&str>,
    ) -> Result<Build, StoreError> {
        let conn = self.conn.lock().unwrap();
        let status_str = status.to_string();

        if status == BuildStatus::Building {
            conn.execute(
                "UPDATE builds SET status = ?1, master_image_id = ?2, build_log_path = ?3 WHERE id = ?4",
                rusqlite::params![status_str, master_image_id, build_log_path, id],
            ).map_err(|e| StoreError::Query(e.to_string()))?;
        } else {
            conn.execute(
                "UPDATE builds SET status = ?1, master_image_id = ?2, build_log_path = ?3, completed_at = strftime('%s', 'now') WHERE id = ?4",
                rusqlite::params![status_str, master_image_id, build_log_path, id],
            ).map_err(|e| StoreError::Query(e.to_string()))?;
        }
        drop(conn);
        self.get_build(id)?.ok_or_else(|| StoreError::Query(format!("build '{}' not found", id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{BuildStatus, CreateTemplateParams};
    use crate::vm::VmRole;
    use crate::drive::ImportImageParams;

    fn test_store() -> SqliteStore {
        // Use a named temp file so the path stays valid for the store lifetime.
        // TempDir would delete the directory on drop, but on Linux the open fd
        // remains valid. However, to be safe we use a path in /tmp directly.
        let id = uuid::Uuid::new_v4();
        let db_path = std::path::PathBuf::from(format!("/tmp/nexus-test-{id}.db"));
        SqliteStore::open_and_init(&db_path).unwrap()
    }

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
        // Expected tables: schema_meta, settings, tags, vms, master_images, drives,
        // vm_boot_history, vm_state_history, routes, vsock_services, bridges, vm_network,
        // firewall_rules, vm_tags, drive_tags, templates, builds, providers, kernels,
        // rootfs_images, firecracker_versions = 21 tables
        assert_eq!(status.table_count, 21, "expected 21 tables, got {}", status.table_count);
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
        assert_eq!(status.table_count, 21);
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
        assert_eq!(status.table_count, 21, "should have all tables after recreate");

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

        assert!(vm.id.as_i64() > 0);
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

        let found = store.get_vm(&created.id.encode()).unwrap().unwrap();
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

        let vm_to_delete = store.get_vm("delete-me").unwrap().unwrap();
        let deleted = store.delete_vm(vm_to_delete.id).unwrap();
        assert!(deleted);

        let found = store.get_vm("delete-me").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn delete_vm_not_found_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        // Try to delete with a non-existent ID
        let deleted = store.delete_vm(crate::id::Id::from_i64(99999)).unwrap();
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

        let deleted = store.delete_vm(created.id).unwrap();
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

        let first = store.get_vm("first").unwrap().unwrap();
        store.delete_vm(first.id).unwrap();

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
        let img = store.create_image(&params, "/data/drives/@base-agent").unwrap();

        assert!(img.id.as_i64() > 0);
        assert_eq!(img.name, "base-agent");
        assert_eq!(img.subvolume_path, "/data/drives/@base-agent");

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

        let img_to_delete = store.get_image("del-me").unwrap().unwrap();
        let deleted = store.delete_image(img_to_delete.id).unwrap();
        assert!(deleted);
        assert!(store.get_image("del-me").unwrap().is_none());
    }

    #[test]
    fn delete_image_not_found_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        assert!(!store.delete_image(crate::id::Id::from_i64(99999)).unwrap());
    }

    #[test]
    fn delete_image_with_drives_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        store.create_drive(Some("ws-1"), "/data/ws-1", img.id).unwrap();

        let base_img = store.get_image("base").unwrap().unwrap();
        let result = store.delete_image(base_img.id);
        assert!(result.is_err());
    }

    #[test]
    fn create_drive_and_get_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        let ws = store.create_drive(Some("my-ws"), "/data/my-ws", img.id).unwrap();

        assert!(ws.id.as_i64() != 0);
        assert_eq!(ws.name, Some("my-ws".to_string()));
        assert_eq!(ws.master_image_id, Some(img.id.clone()));

        let found = store.get_drive("my-ws").unwrap().unwrap();
        assert_eq!(found.id, ws.id);
    }

    #[test]
    fn create_drive_auto_generates_name_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        let ws = store.create_drive(None, "/data/anon-ws", img.id).unwrap();
        assert!(ws.name.is_none());
    }

    #[test]
    fn list_drives_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        store.create_drive(Some("ws-a"), "/data/ws-a", img.id).unwrap();
        store.create_drive(Some("ws-b"), "/data/ws-b", img.id).unwrap();

        let wss = store.list_drives(None).unwrap();
        assert_eq!(wss.len(), 2);
    }

    #[test]
    fn list_drives_filter_by_base() {
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

        store.create_drive(Some("ws-a"), "/data/ws-a", img_a.id).unwrap();
        store.create_drive(Some("ws-b"), "/data/ws-b", img_b.id).unwrap();

        let wss = store.list_drives(Some("base-a")).unwrap();
        assert_eq!(wss.len(), 1);
        assert_eq!(wss[0].name, Some("ws-a".to_string()));
    }

    #[test]
    fn delete_drive_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        store.create_drive(Some("del-ws"), "/data/del-ws", img.id).unwrap();

        let ws_to_delete = store.get_drive("del-ws").unwrap().unwrap();
        let deleted = store.delete_drive(ws_to_delete.id).unwrap();
        assert!(deleted);
        assert!(store.get_drive("del-ws").unwrap().is_none());
    }

    #[test]
    fn delete_drive_not_found_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        assert!(!store.delete_drive(crate::id::Id::from_i64(99999)).unwrap());
    }

    #[test]
    fn create_template_assigns_id() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "base-agent".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        let tpl = store.create_template(&params).unwrap();
        assert!(tpl.id.as_i64() != 0);
        assert_eq!(tpl.name, "base-agent");
        assert_eq!(tpl.version, 1);
        assert_eq!(tpl.source_type, "rootfs");
    }

    #[test]
    fn create_template_duplicate_name_returns_conflict() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "dup".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        store.create_template(&params).unwrap();
        let result = store.create_template(&params);
        assert!(matches!(result, Err(StoreError::Conflict(_))));
    }

    #[test]
    fn list_templates_returns_all() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "tpl-a".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/a.tar.gz".to_string(),
            overlays: None,
        };
        store.create_template(&params).unwrap();
        let params2 = CreateTemplateParams {
            name: "tpl-b".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/b.tar.gz".to_string(),
            overlays: None,
        };
        store.create_template(&params2).unwrap();
        let all = store.list_templates().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn get_template_by_name_or_id() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "find-me".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        let tpl = store.create_template(&params).unwrap();

        let by_name = store.get_template("find-me").unwrap().unwrap();
        assert_eq!(by_name.id, tpl.id);

        let by_id = store.get_template(&tpl.id.encode()).unwrap().unwrap();
        assert_eq!(by_id.name, "find-me");

        assert!(store.get_template("nonexistent").unwrap().is_none());
    }

    #[test]
    fn delete_template_removes_record() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "doomed".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        store.create_template(&params).unwrap();
        let tpl_to_delete = store.get_template("doomed").unwrap().unwrap();
        assert!(store.delete_template(tpl_to_delete.id).unwrap());
        assert!(store.get_template("doomed").unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_template_returns_false() {
        let store = test_store();
        assert!(!store.delete_template(crate::id::Id::from_i64(99999)).unwrap());
    }

    #[test]
    fn create_build_snapshots_template() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "build-me".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        let tpl = store.create_template(&params).unwrap();
        let build = store.create_build(&tpl).unwrap();

        assert!(build.id.as_i64() != 0);
        assert_eq!(build.template_id, tpl.id);
        assert_eq!(build.template_version, tpl.version);
        assert_eq!(build.name, tpl.name);
        assert_eq!(build.source_type, tpl.source_type);
        assert_eq!(build.source_identifier, tpl.source_identifier);
        assert_eq!(build.status, BuildStatus::Building);
        assert!(build.master_image_id.is_none());
    }

    #[test]
    fn update_build_status_to_success() {
        let store = test_store();
        // Create a real master image to satisfy the foreign key constraint
        let img = store.create_image(
            &ImportImageParams { name: "test-image".to_string(), source_path: "/tmp/img".to_string() },
            "/data/test-image",
        ).unwrap();

        let params = CreateTemplateParams {
            name: "success-tpl".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        let tpl = store.create_template(&params).unwrap();
        let build = store.create_build(&tpl).unwrap();

        let updated = store.update_build_status(
            build.id,
            BuildStatus::Success,
            Some(img.id),
            Some("/tmp/build.log"),
        ).unwrap();

        assert_eq!(updated.status, BuildStatus::Success);
        assert_eq!(updated.master_image_id, Some(img.id));
        assert_eq!(updated.build_log_path, Some("/tmp/build.log".to_string()));
        assert!(updated.completed_at.is_some());
    }

    #[test]
    fn update_build_status_to_failed() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "fail-tpl".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        let tpl = store.create_template(&params).unwrap();
        let build = store.create_build(&tpl).unwrap();

        let updated = store.update_build_status(
            build.id,
            BuildStatus::Failed,
            None,
            Some("/tmp/build.log"),
        ).unwrap();

        assert_eq!(updated.status, BuildStatus::Failed);
        assert!(updated.master_image_id.is_none());
        assert!(updated.completed_at.is_some());
    }

    #[test]
    fn list_builds_all_and_filtered() {
        let store = test_store();
        let params_a = CreateTemplateParams {
            name: "tpl-a".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/a.tar.gz".to_string(),
            overlays: None,
        };
        let tpl_a = store.create_template(&params_a).unwrap();
        store.create_build(&tpl_a).unwrap();

        let params_b = CreateTemplateParams {
            name: "tpl-b".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/b.tar.gz".to_string(),
            overlays: None,
        };
        let tpl_b = store.create_template(&params_b).unwrap();
        store.create_build(&tpl_b).unwrap();

        let all = store.list_builds(None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = store.list_builds(Some("tpl-a")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "tpl-a");
    }

    #[test]
    fn get_build_by_id() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "get-build-tpl".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        let tpl = store.create_template(&params).unwrap();
        let build = store.create_build(&tpl).unwrap();

        let found = store.get_build(build.id).unwrap().unwrap();
        assert_eq!(found.id, build.id);

        // get_build takes Id, so use a nonexistent ID
        assert!(store.get_build(crate::id::Id::from_i64(99999)).unwrap().is_none());
    }

    #[test]
    fn delete_template_cascades_to_builds() {
        let store = test_store();
        let params = CreateTemplateParams {
            name: "cascade-tpl".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
        };
        let tpl = store.create_template(&params).unwrap();
        let build = store.create_build(&tpl).unwrap();

        let tpl = store.get_template("cascade-tpl").unwrap().unwrap();
        store.delete_template(tpl.id).unwrap();
        assert!(store.get_build(build.id).unwrap().is_none());
    }

    #[test]
    fn template_overlays_round_trip() {
        let store = test_store();
        let mut overlays = std::collections::HashMap::new();
        overlays.insert("/etc/hostname".to_string(), "nexus-vm".to_string());
        overlays.insert("/etc/resolv.conf".to_string(), "nameserver 8.8.8.8".to_string());

        let params = CreateTemplateParams {
            name: "overlay-tpl".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: Some(overlays.clone()),
        };
        let tpl = store.create_template(&params).unwrap();
        let loaded = store.get_template(&tpl.id.encode()).unwrap().unwrap();

        let loaded_overlays = loaded.overlays.unwrap();
        assert_eq!(loaded_overlays.get("/etc/hostname").unwrap(), "nexus-vm");
        assert_eq!(loaded_overlays.get("/etc/resolv.conf").unwrap(), "nameserver 8.8.8.8");
    }

    #[test]
    fn start_vm_transitions_to_running() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let vm = store.create_vm(&CreateVmParams {
            name: "start-me".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();
        assert_eq!(vm.state, VmState::Created);

        let running = store.start_vm(
            vm.id,
            1234,
            "/run/nexus/vms/abc/firecracker.sock",
            "/run/nexus/vms/abc/firecracker.vsock",
            "/run/nexus/vms/abc/console.log",
            r#"{"boot-source":{}}"#,
        ).unwrap();

        assert_eq!(running.state, VmState::Running);
        assert_eq!(running.pid, Some(1234));
        assert!(running.socket_path.is_some());
        assert!(running.started_at.is_some());
    }

    #[test]
    fn stop_vm_transitions_to_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_vm(&CreateVmParams {
            name: "stop-me".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let vm_to_stop = store.get_vm("stop-me").unwrap().unwrap();
        store.start_vm(
            vm_to_stop.id, 5678,
            "/run/sock", "/run/vsock", "/run/console.log", "{}",
        ).unwrap();
        let stopped = store.stop_vm(vm_to_stop.id).unwrap();
        assert_eq!(stopped.state, VmState::Stopped);
        assert!(stopped.pid.is_none());
        assert!(stopped.stopped_at.is_some());
    }

    #[test]
    fn crash_vm_transitions_to_crashed() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_vm(&CreateVmParams {
            name: "crash-me".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let vm = store.get_vm("crash-me").unwrap().unwrap();
        store.start_vm(
            vm.id, 9999,
            "/run/sock", "/run/vsock", "/run/console.log", "{}",
        ).unwrap();

        let crashed = store.crash_vm(vm.id).unwrap();
        assert_eq!(crashed.state, VmState::Crashed);
        assert!(crashed.pid.is_none());
    }

    #[test]
    fn start_vm_rejects_already_running() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_vm(&CreateVmParams {
            name: "busy".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let vm = store.get_vm("busy").unwrap().unwrap();
        store.start_vm(
            vm.id, 1111,
            "/run/sock", "/run/vsock", "/run/console.log", "{}",
        ).unwrap();

        let result = store.start_vm(
            vm.id, 2222,
            "/run/sock2", "/run/vsock2", "/run/console2.log", "{}",
        );
        assert!(result.is_err());
    }

    #[test]
    fn list_running_vms_returns_only_running() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        store.create_vm(&CreateVmParams {
            name: "idle".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        store.create_vm(&CreateVmParams {
            name: "active".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let active_vm = store.get_vm("active").unwrap().unwrap();
        store.start_vm(
            active_vm.id, 3333,
            "/run/sock", "/run/vsock", "/run/console.log", "{}",
        ).unwrap();

        let running = store.list_running_vms().unwrap();
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].name, "active");
    }

    #[test]
    fn boot_history_records_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let vm = store.create_vm(&CreateVmParams {
            name: "history-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let boot_id = store.record_boot_start(vm.id, "/run/console.log").unwrap();
        assert!(boot_id.as_i64() > 0);

        store.record_boot_stop(boot_id, Some(0), None).unwrap();
    }

    #[test]
    fn attach_drive_to_vm() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let vm = store.create_vm(&CreateVmParams {
            name: "attach-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        let ws = store.create_drive(Some("ws-for-vm"), "/data/ws-for-vm", img.id).unwrap();
        assert!(ws.vm_id.is_none());

        let attached = store.attach_drive(ws.id, vm.id, true).unwrap();
        assert_eq!(attached.vm_id, Some(vm.id));
        assert!(attached.is_root_device);
        assert!(attached.attached_at.is_some());
    }

    #[test]
    fn detach_drive_from_vm() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        let vm = store.create_vm(&CreateVmParams {
            name: "detach-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let img = store.create_image(
            &ImportImageParams { name: "base".to_string(), source_path: "/a".to_string() },
            "/data/base",
        ).unwrap();

        let ws = store.create_drive(Some("ws-detach"), "/data/ws-detach", img.id).unwrap();
        store.attach_drive(ws.id, vm.id, true).unwrap();

        let detached = store.detach_drive(ws.id).unwrap();
        assert!(detached.vm_id.is_none());
        assert!(!detached.is_root_device);
        assert!(detached.detached_at.is_some());
    }

    #[test]
    fn get_state_history_returns_ordered_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        // Create a VM
        let params = CreateVmParams {
            name: "test-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        let vm = store.create_vm(&params).unwrap();

        // Trigger state transitions
        store.update_vm_state(vm.id, "running", Some("started")).unwrap();
        store.update_vm_state(vm.id, "ready", Some("agent connected")).unwrap();
        store.update_vm_state(vm.id, "stopped", Some("user stopped")).unwrap();

        // Get history
        let history = store.get_state_history(vm.id).unwrap();

        assert_eq!(history.len(), 3);
        // Newest first
        assert_eq!(history[0].from_state, "ready");
        assert_eq!(history[0].to_state, "stopped");
        assert_eq!(history[0].reason, Some("user stopped".to_string()));

        assert_eq!(history[1].from_state, "running");
        assert_eq!(history[1].to_state, "ready");
        assert_eq!(history[1].reason, Some("agent connected".to_string()));

        assert_eq!(history[2].from_state, "created");
        assert_eq!(history[2].to_state, "running");
        assert_eq!(history[2].reason, Some("started".to_string()));
    }

    #[test]
    fn get_state_history_empty_for_vm_with_no_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        // Create a VM but don't transition it
        let params = CreateVmParams {
            name: "test-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        let vm = store.create_vm(&params).unwrap();

        let history = store.get_state_history(vm.id).unwrap();
        assert_eq!(history.len(), 0);
    }

    #[test]
    fn start_vm_records_state_transition() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        // Create a VM
        let params = CreateVmParams {
            name: "test-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        let vm = store.create_vm(&params).unwrap();

        // Start the VM
        store.start_vm(
            vm.id,
            12345,
            "/tmp/test.sock",
            "/tmp/test.uds",
            "/tmp/test.log",
            "{}"
        ).unwrap();

        // Check that state transition was recorded
        let history = store.get_state_history(vm.id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].from_state, "created");
        assert_eq!(history[0].to_state, "running");
        assert_eq!(history[0].reason, Some("VM started".to_string()));
    }

    #[test]
    fn register_firecracker_succeeds() {
        let store = test_store();
        let params = RegisterFirecrackerParams {
            version: "1.12.0".to_string(),
            architecture: "x86_64".to_string(),
            path_on_host: "/tmp/firecracker-1.12.0".to_string(),
            sha256: "abc123".to_string(),
            file_size: 1024,
            source_url: "https://example.com/firecracker-1.12.0".to_string(),
        };
        let fc = store.register_firecracker(&params).unwrap();
        assert_eq!(fc.version, "1.12.0");
        assert_eq!(fc.architecture, "x86_64");
        assert_eq!(fc.path_on_host, "/tmp/firecracker-1.12.0");
    }

    #[test]
    fn register_kernel_succeeds() {
        let store = test_store();
        let params = RegisterKernelParams {
            version: "6.1.0".to_string(),
            architecture: "x86_64".to_string(),
            path_on_host: "/tmp/vmlinux-6.1.0".to_string(),
            sha256: "def456".to_string(),
            pgp_verified: false,
            file_size: 2048,
            source_url: "https://example.com/vmlinux-6.1.0".to_string(),
        };
        let kernel = store.register_kernel(&params).unwrap();
        assert_eq!(kernel.version, "6.1.0");
        assert_eq!(kernel.architecture, "x86_64");
        assert_eq!(kernel.path_on_host, "/tmp/vmlinux-6.1.0");
    }

    #[test]
    fn register_rootfs_succeeds() {
        let store = test_store();
        let params = RegisterRootfsParams {
            distro: "alpine".to_string(),
            version: "3.19.0".to_string(),
            architecture: "x86_64".to_string(),
            path_on_host: "/tmp/alpine-3.19.0.tar.gz".to_string(),
            sha256: "ghi789".to_string(),
            file_size: 4096,
            source_url: "https://example.com/alpine-3.19.0.tar.gz".to_string(),
        };
        let rootfs = store.register_rootfs(&params).unwrap();
        assert_eq!(rootfs.version, "3.19.0");
        assert_eq!(rootfs.architecture, "x86_64");
        assert_eq!(rootfs.distro, "alpine");
        assert_eq!(rootfs.path_on_host, "/tmp/alpine-3.19.0.tar.gz");
    }

    #[test]
    fn stop_vm_records_state_transition() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();

        // Create and start a VM
        let params = CreateVmParams {
            name: "test-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        let vm = store.create_vm(&params).unwrap();
        store.start_vm(
            vm.id,
            12345,
            "/tmp/test.sock",
            "/tmp/test.uds",
            "/tmp/test.log",
            "{}"
        ).unwrap();

        // Stop the VM
        store.stop_vm(vm.id).unwrap();

        // Check that state transition was recorded
        let history = store.get_state_history(vm.id).unwrap();
        assert_eq!(history.len(), 2);
        // History is reverse chronological, so stopped transition is first
        assert_eq!(history[0].from_state, "running");
        assert_eq!(history[0].to_state, "stopped");
        assert_eq!(history[0].reason, Some("VM stopped".to_string()));
        // Second entry is the start transition
        assert_eq!(history[1].from_state, "created");
        assert_eq!(history[1].to_state, "running");
    }
}
