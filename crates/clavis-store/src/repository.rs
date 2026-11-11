//! Repository operations: transactional revision persistence with head and
//! generation management, pending-upload markers and stale-edit rejection.
//! Only ciphertext and non-secret metadata are stored.

use clavis_core::error::CoreError;
use clavis_core::ids::{RevisionId, VaultId};
use clavis_core::vault::format::parse_container;

use crate::db::Store;

pub fn register_vault(
    store: &Store,
    vault_id: &VaultId,
    name: Option<&str>,
    provider_kind: Option<&str>,
    active: bool,
) -> Result<(), CoreError> {
    store.tx(|conn| {
        conn.execute(
            "INSERT INTO vaults (vault_id, name, provider_kind, active) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(vault_id) DO UPDATE SET name = excluded.name,
               provider_kind = excluded.provider_kind, active = excluded.active",
            rusqlite::params![vault_id.to_string(), name, provider_kind, active as i64],
        )
        .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    })
}

pub fn active_vault(store: &Store) -> Result<Option<String>, CoreError> {
    store.with_conn(|conn| {
        let mut stmt = conn
            .prepare("SELECT vault_id FROM vaults WHERE active = 1 LIMIT 1")
            .map_err(|_| CoreError::StorageFailure)?;
        let mut rows = stmt.query([]).map_err(|_| CoreError::StorageFailure)?;
        if let Some(row) = rows.next().map_err(|_| CoreError::StorageFailure)? {
            Ok(Some(row.get(0).map_err(|_| CoreError::StorageFailure)?))
        } else {
            Ok(None)
        }
    })
}

pub fn set_active_vault(store: &Store, vault_id: &str) -> Result<(), CoreError> {
    store.tx(|conn| {
        conn.execute("UPDATE vaults SET active = 0", [])
            .map_err(|_| CoreError::StorageFailure)?;
        conn.execute(
            "UPDATE vaults SET active = 1 WHERE vault_id = ?1",
            [vault_id],
        )
        .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    })
}

pub type VaultRow = (String, Option<String>, Option<String>, bool);

pub fn list_vaults(store: &Store) -> Result<Vec<VaultRow>, CoreError> {
    store.with_conn(|conn| {
        let mut stmt = conn
            .prepare("SELECT vault_id, name, provider_kind, active FROM vaults")
            .map_err(|_| CoreError::StorageFailure)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)? != 0,
                ))
            })
            .map_err(|_| CoreError::StorageFailure)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| CoreError::StorageFailure)
    })
}

pub fn revision_ids(store: &Store, vault_id: &VaultId) -> Result<Vec<RevisionId>, CoreError> {
    store.with_conn(|conn| {
        let mut stmt = conn
            .prepare("SELECT revision_id FROM revisions WHERE vault_id = ?1")
            .map_err(|_| CoreError::StorageFailure)?;
        let rows = stmt
            .query_map([vault_id.to_string()], |row| {
                let s: String = row.get(0)?;
                Ok(s)
            })
            .map_err(|_| CoreError::StorageFailure)?;
        let mut out = Vec::new();
        for r in rows {
            let s = r.map_err(|_| CoreError::StorageFailure)?;
            let uuid = s.parse().map_err(|_| CoreError::IntegrityFailure)?;
            out.push(RevisionId(uuid));
        }
        Ok(out)
    })
}

pub fn load_blob(
    store: &Store,
    vault_id: &VaultId,
    revision_id: &RevisionId,
) -> Result<Option<Vec<u8>>, CoreError> {
    store.with_conn(|conn| {
        let mut stmt = conn
            .prepare("SELECT blob FROM revisions WHERE vault_id = ?1 AND revision_id = ?2")
            .map_err(|_| CoreError::StorageFailure)?;
        let mut rows = stmt
            .query(rusqlite::params![
                vault_id.to_string(),
                revision_id.to_string()
            ])
            .map_err(|_| CoreError::StorageFailure)?;
        if let Some(row) = rows.next().map_err(|_| CoreError::StorageFailure)? {
            Ok(Some(row.get(0).map_err(|_| CoreError::StorageFailure)?))
        } else {
            Ok(None)
        }
    })
}

/// Current heads and the local generation counter for staleness checks.
pub fn read_heads(store: &Store, vault_id: &VaultId) -> Result<(Vec<RevisionId>, u64), CoreError> {
    store.with_conn(|conn| {
        let mut stmt = conn
            .prepare("SELECT head_ids, generation FROM heads WHERE vault_id = ?1")
            .map_err(|_| CoreError::StorageFailure)?;
        let mut rows = stmt
            .query([vault_id.to_string()])
            .map_err(|_| CoreError::StorageFailure)?;
        if let Some(row) = rows.next().map_err(|_| CoreError::StorageFailure)? {
            let ids: String = row.get(0).map_err(|_| CoreError::StorageFailure)?;
            let generation: i64 = row.get(1).map_err(|_| CoreError::StorageFailure)?;
            let parsed: Vec<String> =
                serde_json::from_str(&ids).map_err(|_| CoreError::StorageFailure)?;
            let heads = parsed
                .into_iter()
                .map(|s| {
                    s.parse()
                        .map(RevisionId)
                        .map_err(|_| CoreError::IntegrityFailure)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((heads, generation as u64))
        } else {
            Ok((Vec::new(), 0))
        }
    })
}

fn write_heads_tx(
    conn: &rusqlite::Connection,
    vault_id: &VaultId,
    heads: &[RevisionId],
    generation: u64,
) -> Result<(), CoreError> {
    let ids: Vec<String> = heads.iter().map(|r| r.to_string()).collect();
    conn.execute(
        "INSERT INTO heads (vault_id, head_ids, generation) VALUES (?1, ?2, ?3)
         ON CONFLICT(vault_id) DO UPDATE SET head_ids = excluded.head_ids,
           generation = excluded.generation",
        rusqlite::params![
            vault_id.to_string(),
            serde_json::to_string(&ids).map_err(|_| CoreError::StorageFailure)?,
            generation as i64
        ],
    )
    .map_err(|_| CoreError::StorageFailure)?;
    Ok(())
}

/// Update the recorded head set and generation after a merge (no new local
/// revision is created by remote merges).
pub fn update_heads(
    store: &Store,
    vault_id: &VaultId,
    heads: &[RevisionId],
    generation: u64,
) -> Result<(), CoreError> {
    store.tx(|conn| write_heads_tx(conn, vault_id, heads, generation))
}

/// Insert a downloaded remote revision (no outbox row). Idempotent per
/// revision ID.
pub fn insert_remote_revision(
    store: &Store,
    vault_id: &VaultId,
    blob: &[u8],
    new_heads: &[RevisionId],
    generation: u64,
) -> Result<(), CoreError> {
    let parsed = parse_container(blob)?;
    if VaultId(parsed.header.vault_id) != *vault_id {
        return Err(CoreError::IntegrityFailure);
    }
    let record_kind = match parsed.header.record_kind {
        clavis_core::vault::format::RecordKind::Vault => "vault",
        clavis_core::vault::format::RecordKind::Retirement => "retirement",
    };
    let revision_id = RevisionId(parsed.header.revision_id);
    store.tx(|conn| {
        conn.execute(
            "INSERT OR IGNORE INTO revisions (vault_id, revision_id, blob, record_kind)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                vault_id.to_string(),
                revision_id.to_string(),
                blob,
                record_kind
            ],
        )
        .map_err(|_| CoreError::StorageFailure)?;
        write_heads_tx(conn, vault_id, new_heads, generation)?;
        Ok(())
    })
}

/// Seal + commit a local edit in one transaction: the sealed blob and its
/// pending-upload marker become durable together before "Saved" is reported.
/// `expected_generation` must match the stored generation or the edit is
/// rejected as stale; a set write barrier blocks writes during migration.
pub fn commit_local_revision(
    store: &Store,
    vault_id: &VaultId,
    blob: &[u8],
    parents: &[RevisionId],
    expected_generation: u64,
) -> Result<RevisionId, CoreError> {
    let parsed = parse_container(blob)?;
    if VaultId(parsed.header.vault_id) != *vault_id {
        return Err(CoreError::IntegrityFailure);
    }
    let revision_id = RevisionId(parsed.header.revision_id);
    // Verify parents are exactly the current heads.
    let (current_heads, generation) = read_heads(store, vault_id)?;
    if generation != expected_generation {
        return Err(CoreError::StaleRevision);
    }
    let mut sorted_current = current_heads.clone();
    sorted_current.sort();
    let mut sorted_parents = parents.to_vec();
    sorted_parents.sort();
    if sorted_current != sorted_parents {
        return Err(CoreError::StaleRevision);
    }
    if store.is_write_barrier_set(&vault_id.to_string())? {
        return Err(CoreError::InvalidInput(
            "vault is migrating; local edits are blocked",
        ));
    }
    let new_heads = vec![revision_id];
    store.tx(|conn| {
        // Re-check inside the transaction: two writers in one process are
        // serialized by the store mutex; cross-process writers are rejected
        // by the generation check re-read here.
        let (_, gen_now) = {
            let mut stmt = conn
                .prepare("SELECT head_ids, generation FROM heads WHERE vault_id = ?1")
                .map_err(|_| CoreError::StorageFailure)?;
            let mut rows = stmt
                .query([vault_id.to_string()])
                .map_err(|_| CoreError::StorageFailure)?;
            if let Some(row) = rows.next().map_err(|_| CoreError::StorageFailure)? {
                let gen: i64 = row.get(1).map_err(|_| CoreError::StorageFailure)?;
                Ok(((), gen as u64))
            } else {
                Ok(((), 0u64))
            }
        }?;
        if gen_now != expected_generation {
            return Err(CoreError::StaleRevision);
        }
        conn.execute(
            "INSERT OR IGNORE INTO revisions (vault_id, revision_id, blob, record_kind)
             VALUES (?1, ?2, ?3, 'vault')",
            rusqlite::params![vault_id.to_string(), revision_id.to_string(), blob],
        )
        .map_err(|_| CoreError::StorageFailure)?;
        conn.execute(
            "INSERT OR IGNORE INTO outbox (vault_id, revision_id, blob, state)
             VALUES (?1, ?2, ?3, 'pending')",
            rusqlite::params![vault_id.to_string(), revision_id.to_string(), blob],
        )
        .map_err(|_| CoreError::StorageFailure)?;
        write_heads_tx(conn, vault_id, &new_heads, expected_generation + 1)?;
        Ok(())
    })?;
    Ok(revision_id)
}

/// Device counter management: transactional allocation of the next
/// operation-dot counter for this device.
pub fn next_device_counter(store: &Store) -> Result<u64, CoreError> {
    store.tx(|conn| {
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('device_counter', '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)",
            [],
        )
        .map_err(|_| CoreError::StorageFailure)?;
        let v: String = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'device_counter'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| CoreError::StorageFailure)?;
        // The counter we return is the value BEFORE increment semantics used
        // by callers: this function returns the newly allocated counter.
        v.parse::<u64>().map_err(|_| CoreError::StorageFailure)
    })
}

pub fn device_id(store: &Store) -> Result<String, CoreError> {
    if let Some(id) = store.config_get("device_id")? {
        return Ok(id);
    }
    let id = clavis_core::ids::DeviceId::generate().0.to_string();
    store.config_set("device_id", &id)?;
    Ok(id)
}
