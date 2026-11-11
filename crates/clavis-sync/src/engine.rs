//! Sync engine: pull → validate → merge → push, with truthful status. Never
//! displays Synced until local work is confirmed remote and the discovered
//! graph is merged. Pending upload bytes remain durable through failures.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clavis_core::error::CoreError;
use clavis_core::ids::VaultId;
use clavis_core::vault::keys::UnlockedVault;
use clavis_store::db::Store;
use clavis_store::{outbox, repository};

use crate::graph::{validate_graph, RevisionNode};
use crate::merge::merge_heads;
use crate::transport::{digest, RemoteStore, SyncError};

/// Cancellation token for long operations; locked/canceled sessions must not
/// commit work.
#[derive(Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Cancel(Arc::new(AtomicBool::new(false)))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncTrigger {
    Unlock,
    Resume,
    NetworkRestored,
    BeforeUpload,
    Poll,
    Manual,
    Edit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub status: clavis_core::dto::SyncStatusKind,
    pub downloaded: u64,
    pub uploaded: u64,
    pub pending: u64,
    pub has_conflicts: bool,
    /// None when the report is not tied to a concrete moment.
    pub last_confirmed_sync_unix: Option<u64>,
}

/// One sync pass for a vault against a provider connection. Workers per
/// local vault are serialized by the caller.
pub async fn sync_once(
    store: &Store,
    vault: &UnlockedVault,
    remote: &dyn RemoteStore,
    cancel: &Cancel,
    trigger: SyncTrigger,
    now_unix: u64,
) -> Result<SyncReport, SyncError> {
    if cancel.is_canceled() {
        return Err(SyncError::Canceled);
    }
    let vault_id = vault.vault_id;
    let _ = trigger;

    // 1. Discover revisions across all pages.
    let mut objects = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        if cancel.is_canceled() {
            return Err(SyncError::Canceled);
        }
        let page = remote.list_page(&vault_id, cursor.as_deref()).await?;
        for obj in page.objects {
            // Duplicate listings for one revision are accepted only when
            // byte-identical; differing digests are an integrity error.
            if let Some(existing) = objects
                .iter_mut()
                .find(|o: &&mut crate::transport::RemoteObject| o.revision_id == obj.revision_id)
            {
                match (existing.digest, obj.digest) {
                    (Some(a), Some(b)) if a == b => {}
                    (None, Some(b)) => existing.digest = Some(b),
                    (Some(_a), None) => {}
                    _ => return Err(SyncError::IntegrityFailure),
                }
                continue;
            }
            objects.push(obj);
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    // 2. Download unknown revisions.
    let known: std::collections::BTreeSet<String> = repository::revision_ids(store, &vault_id)?
        .into_iter()
        .map(|r| r.to_string())
        .collect();
    let mut downloaded = 0u64;
    for obj in &objects {
        if known.contains(&obj.revision_id.to_string()) {
            continue;
        }
        if cancel.is_canceled() {
            return Err(SyncError::Canceled);
        }
        let bytes = remote.get_object(&obj.locator).await?;
        if let Some(expected) = obj.digest {
            if digest(&bytes) != expected {
                return Err(SyncError::IntegrityFailure);
            }
        }
        // Size cap: reject oversized objects before storing.
        if bytes.len() > clavis_core::vault::format::MAX_OBJECT_LEN {
            return Err(SyncError::OtherSanitized("object size limit exceeded"));
        }
        let parsed = clavis_core::vault::format::parse_container(&bytes)?;
        if VaultId(parsed.header.vault_id) != vault_id {
            return Err(SyncError::IntegrityFailure);
        }
        let (_, gen) = repository::read_heads(store, &vault_id)?;
        repository::insert_remote_revision(store, &vault_id, &bytes, &[obj.revision_id], gen)?;
        downloaded += 1;
    }

    // 3. Validate and merge the full graph.
    let ids = repository::revision_ids(store, &vault_id)?;
    let mut nodes = Vec::new();
    for rid in ids {
        let blob =
            repository::load_blob(store, &vault_id, &rid)?.ok_or(SyncError::IntegrityFailure)?;
        nodes.push(RevisionNode {
            revision_id: rid,
            parents: Vec::new(),
            blob,
        });
    }
    let graph = match validate_graph(&vault_id, &nodes) {
        Ok(g) => g,
        Err(crate::graph::GraphError::MissingParents(_)) => {
            // Incomplete sync: keep the last consistent local state; never
            // take an arbitrary head. Do not report Synced.
            let pending = outbox::count_pending(store, &vault_id)?;
            return Ok(SyncReport {
                status: if pending > 0 {
                    clavis_core::dto::SyncStatusKind::Pending
                } else {
                    clavis_core::dto::SyncStatusKind::Syncing
                },
                downloaded,
                uploaded: 0,
                pending,
                has_conflicts: false,
                last_confirmed_sync_unix: None,
            });
        }
        Err(crate::graph::GraphError::Core(CoreError::IntegrityFailure)) => {
            return Err(SyncError::IntegrityFailure)
        }
        Err(crate::graph::GraphError::Core(e)) => return Err(e.into()),
    };
    let merged = merge_heads(&graph, vault.root_key())?;
    let (_, generation) = repository::read_heads(store, &vault_id)?;
    repository::update_heads(store, &vault_id, &graph.heads, generation)?;

    // 4. Push pending uploads, idempotent by revision ID.
    let mut uploaded = 0u64;
    for entry in outbox::pending_entries(store, &vault_id)? {
        if cancel.is_canceled() {
            return Err(SyncError::Canceled);
        }
        let receipt = remote
            .create_object(&vault_id, &entry.revision_id, entry.blob.clone())
            .await?;
        let expected = digest(&entry.blob);
        remote.verify_object(&receipt, &expected).await?;
        outbox::mark_uploaded(store, &vault_id, &entry.revision_id)?;
        uploaded += 1;
    }

    // 5. Truthful status.
    let pending = outbox::count_pending(store, &vault_id)?;
    let status = if merged.retirement.is_some() {
        clavis_core::dto::SyncStatusKind::MigrationRequired
    } else if pending > 0 {
        clavis_core::dto::SyncStatusKind::Pending
    } else if merged.has_conflicts {
        clavis_core::dto::SyncStatusKind::Conflict
    } else {
        clavis_core::dto::SyncStatusKind::Synced
    };
    Ok(SyncReport {
        status,
        downloaded,
        uploaded,
        pending,
        has_conflicts: merged.has_conflicts,
        last_confirmed_sync_unix: Some(now_unix),
    })
}
