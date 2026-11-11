//! Pending-upload outbox. Local writes become durable together with their
//! pending-upload marker; retries are idempotent per revision ID.

use clavis_core::error::CoreError;
use clavis_core::ids::{RevisionId, VaultId};

use crate::db::Store;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxState {
    Pending,
    Uploaded,
}

pub struct OutboxEntry {
    pub vault_id: VaultId,
    pub revision_id: RevisionId,
    pub blob: Vec<u8>,
    pub state: OutboxState,
}

pub fn pending_entries(store: &Store, vault_id: &VaultId) -> Result<Vec<OutboxEntry>, CoreError> {
    store.with_conn(|conn| {
        let mut stmt = conn
            .prepare("SELECT revision_id, blob, state FROM outbox WHERE vault_id = ?1 AND state = 'pending' ORDER BY rowid")
            .map_err(|_| CoreError::StorageFailure)?;
        let rows = stmt
            .query_map([vault_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| CoreError::StorageFailure)?;
        let mut out = Vec::new();
        for r in rows {
            let (rid, blob, state) = r.map_err(|_| CoreError::StorageFailure)?;
            out.push(OutboxEntry {
                vault_id: *vault_id,
                revision_id: RevisionId(
                    rid.parse().map_err(|_| CoreError::IntegrityFailure)?,
                ),
                blob,
                state: if state == "uploaded" {
                    OutboxState::Uploaded
                } else {
                    OutboxState::Pending
                },
            });
        }
        Ok(out)
    })
}

pub fn mark_uploaded(
    store: &Store,
    vault_id: &VaultId,
    revision_id: &RevisionId,
) -> Result<(), CoreError> {
    store.tx(|conn| {
        conn.execute(
            "UPDATE outbox SET state = 'uploaded' WHERE vault_id = ?1 AND revision_id = ?2",
            rusqlite::params![vault_id.to_string(), revision_id.to_string()],
        )
        .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    })
}

pub fn count_pending(store: &Store, vault_id: &VaultId) -> Result<u64, CoreError> {
    store.with_conn(|conn| {
        conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE vault_id = ?1 AND state = 'pending'",
            [vault_id.to_string()],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u64)
        .map_err(|_| CoreError::StorageFailure)
    })
}
