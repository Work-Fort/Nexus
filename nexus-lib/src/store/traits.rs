/// Information about the database for status reporting.
#[derive(Debug, Clone)]
pub struct DbStatus {
    /// Path to the database file (or connection string for non-file backends)
    pub path: String,
    /// Number of user tables in the database
    pub table_count: usize,
    /// Size of the database file in bytes (None if not applicable)
    pub size_bytes: Option<u64>,
}

/// Errors from the state store.
#[derive(Debug)]
pub enum StoreError {
    /// Database connection or initialization failed
    Init(String),
    /// Query execution failed
    Query(String),
    /// Schema migration required (version mismatch)
    SchemaMismatch { expected: u32, found: u32 },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Init(e) => write!(f, "store initialization failed: {e}"),
            StoreError::Query(e) => write!(f, "store query failed: {e}"),
            StoreError::SchemaMismatch { expected, found } => {
                write!(f, "schema version mismatch: expected {expected}, found {found}")
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// Storage abstraction trait for future backend swaps.
///
/// All state persistence goes through this trait. The pre-alpha
/// implementation is SQLite; this trait exists so the backend can
/// be swapped to Postgres or etcd for clustering later.
pub trait StateStore {
    /// Initialize the store (create schema if needed, run migrations).
    fn init(&self) -> Result<(), StoreError>;

    /// Return database status information for health/status reporting.
    fn status(&self) -> Result<DbStatus, StoreError>;

    /// Close the store and release resources.
    fn close(&self) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_status_fields_accessible() {
        let status = DbStatus {
            path: "/tmp/test.db".to_string(),
            table_count: 5,
            size_bytes: Some(4096),
        };
        assert_eq!(status.path, "/tmp/test.db");
        assert_eq!(status.table_count, 5);
        assert_eq!(status.size_bytes, Some(4096));
    }

    #[test]
    fn store_error_display() {
        let err = StoreError::Init("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));

        let err = StoreError::SchemaMismatch { expected: 2, found: 1 };
        assert!(err.to_string().contains("expected 2"));
        assert!(err.to_string().contains("found 1"));
    }
}
