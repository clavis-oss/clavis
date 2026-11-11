use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;

use clavis_core::error::CoreError;

/// Open (or create) the local store. The database file is created with
/// user-only permissions and configured for durable transactions.
pub struct Store {
    conn: Mutex<Connection>,
    #[allow(dead_code)] // recorded for diagnostics; not read in v1
    path: PathBuf,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store, CoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| CoreError::StorageFailure)?;
        }
        let created = !path.exists();
        let conn = Connection::open(path).map_err(|_| CoreError::StorageFailure)?;
        if created {
            restrict_permissions(path)?;
        }
        // FULL synchronous + DELETE journal: a crash leaves the last
        // committed transaction intact. WAL/SHM files would carry ciphertext
        // too; DELETE keeps that set smaller and is sufficient here.
        conn.pragma_update(None, "journal_mode", "DELETE")
            .map_err(|_| CoreError::StorageFailure)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|_| CoreError::StorageFailure)?;
        let store = Store {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Store, CoreError> {
        let conn = Connection::open_in_memory().map_err(|_| CoreError::StorageFailure)?;
        let store = Store {
            conn: Mutex::new(conn),
            path: PathBuf::from(":memory:"),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let guard = self.conn.lock().map_err(|_| CoreError::StorageFailure)?;
        f(&guard)
    }

    /// Serialized transaction across the store.
    pub fn tx<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let mut guard = self.conn.lock().map_err(|_| CoreError::StorageFailure)?;
        let tx = guard.transaction().map_err(|_| CoreError::StorageFailure)?;
        let result = f(&tx)?;
        tx.commit().map_err(|_| CoreError::StorageFailure)?;
        Ok(result)
    }

    fn migrate(&self) -> Result<(), CoreError> {
        self.with_conn(|conn| {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vaults (
                    vault_id TEXT PRIMARY KEY,
                    name TEXT,
                    provider_kind TEXT,
                    active INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS revisions (
                    vault_id TEXT NOT NULL,
                    revision_id TEXT NOT NULL,
                    blob BLOB NOT NULL,
                    record_kind TEXT NOT NULL,
                    PRIMARY KEY (vault_id, revision_id)
                );
                CREATE TABLE IF NOT EXISTS heads (
                    vault_id TEXT PRIMARY KEY,
                    head_ids TEXT NOT NULL,
                    generation INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    vault_id TEXT NOT NULL,
                    revision_id TEXT NOT NULL,
                    blob BLOB NOT NULL,
                    state TEXT NOT NULL,
                    PRIMARY KEY (vault_id, revision_id)
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    key TEXT PRIMARY KEY,
                    data BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS migration_journal (
                    migration_id TEXT PRIMARY KEY,
                    journal BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS write_barrier (
                    vault_id TEXT PRIMARY KEY,
                    migrating INTEGER NOT NULL
                );
                "#,
            )
            .map_err(|_| CoreError::StorageFailure)?;
            Ok(())
        })
    }

    pub fn config_get(&self, key: &str) -> Result<Option<String>, CoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT value FROM config WHERE key = ?1")
                .map_err(|_| CoreError::StorageFailure)?;
            let mut rows = stmt.query([key]).map_err(|_| CoreError::StorageFailure)?;
            if let Some(row) = rows.next().map_err(|_| CoreError::StorageFailure)? {
                Ok(Some(
                    row.get::<_, String>(0)
                        .map_err(|_| CoreError::StorageFailure)?,
                ))
            } else {
                Ok(None)
            }
        })
    }

    pub fn config_set(&self, key: &str, value: &str) -> Result<(), CoreError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO config (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [key, value],
            )
            .map_err(|_| CoreError::StorageFailure)?;
            Ok(())
        })
    }

    /// Set the source write barrier during migration: local writers check it
    /// transactionally and cannot save into a migrating source.
    pub fn set_write_barrier(&self, vault_id: &str, migrating: bool) -> Result<(), CoreError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO write_barrier (vault_id, migrating) VALUES (?1, ?2)
                 ON CONFLICT(vault_id) DO UPDATE SET migrating = excluded.migrating",
                [vault_id, if migrating { "1" } else { "0" }],
            )
            .map_err(|_| CoreError::StorageFailure)?;
            Ok(())
        })
    }

    pub fn is_write_barrier_set(&self, vault_id: &str) -> Result<bool, CoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT migrating FROM write_barrier WHERE vault_id = ?1")
                .map_err(|_| CoreError::StorageFailure)?;
            let mut rows = stmt
                .query([vault_id])
                .map_err(|_| CoreError::StorageFailure)?;
            if let Some(row) = rows.next().map_err(|_| CoreError::StorageFailure)? {
                let v: i64 = row.get(0).map_err(|_| CoreError::StorageFailure)?;
                Ok(v != 0)
            } else {
                Ok(false)
            }
        })
    }
}

fn restrict_permissions(path: &Path) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| CoreError::StorageFailure)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| CoreError::StorageFailure)?;
        f.write_all(bytes).map_err(|_| CoreError::StorageFailure)?;
        f.sync_all().map_err(|_| CoreError::StorageFailure)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|_| CoreError::StorageFailure)?;
    }
    Ok(())
}

pub fn read_private_file(path: &Path) -> Result<Option<Vec<u8>>, CoreError> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(CoreError::StorageFailure),
    }
}
