//! Local vault state service: load-and-merge from the encrypted store, and
//! transactional local edits with stale-revision protection.

use clavis_core::causal::{Dot, Field, FieldValue, Snapshot};
use clavis_core::error::CoreError;
use clavis_core::ids::{EntryId, RevisionId, VaultId};
use clavis_core::vault::keys::{seal_revision, UnlockedVault};
use clavis_store::db::Store;
use clavis_store::outbox;
use clavis_store::repository;

use crate::graph::{validate_graph, RevisionNode};
use crate::merge::merge_heads;

pub struct LoadedState {
    pub snapshot: Snapshot,
    pub heads: Vec<RevisionId>,
    pub generation: u64,
    pub retirement: Option<clavis_core::vault::keys::RetirementPayload>,
}

/// Load all local revisions, validate the graph and merge the state. On a
/// validated graph the merged snapshot is authoritative; a missing-parent
/// condition surfaces as `GraphError::MissingParents` so callers keep the
/// last consistent state.
pub fn load_state(
    store: &Store,
    vault_id: &VaultId,
    vault: &UnlockedVault,
) -> Result<LoadedState, CoreError> {
    let ids = repository::revision_ids(store, vault_id)?;
    let mut nodes = Vec::new();
    for rid in ids {
        let blob =
            repository::load_blob(store, vault_id, &rid)?.ok_or(CoreError::IntegrityFailure)?;
        nodes.push(RevisionNode {
            revision_id: rid,
            parents: Vec::new(),
            blob,
        });
    }
    let graph = validate_graph(vault_id, &nodes).map_err(|e| match e {
        crate::graph::GraphError::MissingParents(_) => CoreError::IncompleteSync,
        crate::graph::GraphError::Core(c) => c,
    })?;
    let merged = merge_heads(&graph, vault.root_key())?;
    let (stored_heads, generation) = repository::read_heads(store, vault_id)?;
    let heads = if graph.heads.is_empty() {
        stored_heads
    } else {
        graph.heads
    };
    Ok(LoadedState {
        snapshot: merged.snapshot,
        heads,
        generation,
        retirement: merged.retirement,
    })
}

fn next_dot(store: &Store, vault_id: &VaultId) -> Result<Dot, CoreError> {
    let counter = repository::next_device_counter(store)?;
    let device = repository::device_id(store)?;
    let device_id = device.parse().map_err(|_| CoreError::StorageFailure)?;
    Ok(Dot {
        writer: clavis_core::ids::WriterId(*vault_id, clavis_core::ids::DeviceId(device_id)),
        counter,
    })
}

fn commit(
    store: &Store,
    vault: &UnlockedVault,
    snapshot: &Snapshot,
    heads: &[RevisionId],
    generation: u64,
) -> Result<(RevisionId, u64), CoreError> {
    let blob = seal_revision(vault, snapshot, heads)?;
    let revision_id =
        repository::commit_local_revision(store, &vault.vault_id, &blob.0, heads, generation)?;
    Ok((revision_id, generation + 1))
}

pub struct NewAccount {
    pub issuer: String,
    pub account_label: String,
    pub favorite: bool,
    pub config: clavis_core::otp::OtpConfigValue,
}

pub fn add_account(
    store: &Store,
    vault: &UnlockedVault,
    entry: NewAccount,
    expected_generation: u64,
) -> Result<(EntryId, RevisionId, u64), CoreError> {
    let state = load_state(store, &vault.vault_id, vault)?;
    if state.generation != expected_generation {
        return Err(CoreError::StaleRevision);
    }
    let mut snapshot = state.snapshot;
    let entry_id = EntryId::generate();
    let dot = next_dot(store, &vault.vault_id)?;
    clavis_core::vault::apply_local_action(
        &mut snapshot,
        entry_id,
        dot,
        vec![
            (Field::Issuer, FieldValue::Issuer(entry.issuer)),
            (
                Field::AccountLabel,
                FieldValue::AccountLabel(entry.account_label),
            ),
            (Field::Favorite, FieldValue::Favorite(entry.favorite)),
            (Field::OtpConfig, FieldValue::OtpConfig(entry.config)),
        ],
    )?;
    let (rid, gen) = commit(store, vault, &snapshot, &state.heads, state.generation)?;
    Ok((entry_id, rid, gen))
}

pub struct AccountPatch {
    pub issuer: Option<String>,
    pub account_label: Option<String>,
    pub favorite: Option<bool>,
    /// Full OTP-config replacement is an explicit, atomic operation.
    pub otp_config: Option<clavis_core::otp::OtpConfigValue>,
}

pub fn update_account(
    store: &Store,
    vault: &UnlockedVault,
    entry_id: EntryId,
    patch: AccountPatch,
    expected_generation: u64,
) -> Result<(RevisionId, u64), CoreError> {
    let state = load_state(store, &vault.vault_id, vault)?;
    if state.generation != expected_generation {
        return Err(CoreError::StaleRevision);
    }
    let mut snapshot = state.snapshot;
    // Editing an already deleted entry requires an explicit restore.
    if snapshot
        .accounts
        .get(&entry_id)
        .map(|e| e.is_tombstoned())
        .unwrap_or(false)
    {
        return Err(CoreError::InvalidInput(
            "account is deleted; restore it first",
        ));
    }
    let dot = next_dot(store, &vault.vault_id)?;
    let mut values: Vec<(Field, FieldValue)> = Vec::new();
    if let Some(issuer) = patch.issuer {
        values.push((Field::Issuer, FieldValue::Issuer(issuer)));
    }
    if let Some(label) = patch.account_label {
        values.push((Field::AccountLabel, FieldValue::AccountLabel(label)));
    }
    if let Some(fav) = patch.favorite {
        values.push((Field::Favorite, FieldValue::Favorite(fav)));
    }
    if let Some(cfg) = patch.otp_config {
        cfg.validate()?;
        values.push((Field::OtpConfig, FieldValue::OtpConfig(cfg)));
    }
    if values.is_empty() {
        return Err(CoreError::InvalidInput("empty update"));
    }
    clavis_core::vault::apply_local_action(&mut snapshot, entry_id, dot, values)?;
    let (rid, gen) = commit(store, vault, &snapshot, &state.heads, state.generation)?;
    Ok((rid, gen))
}

pub fn delete_account(
    store: &Store,
    vault: &UnlockedVault,
    entry_id: EntryId,
    expected_generation: u64,
) -> Result<(RevisionId, u64), CoreError> {
    let state = load_state(store, &vault.vault_id, vault)?;
    if state.generation != expected_generation {
        return Err(CoreError::StaleRevision);
    }
    let mut snapshot = state.snapshot;
    let dot = next_dot(store, &vault.vault_id)?;
    clavis_core::vault::apply_local_action(
        &mut snapshot,
        entry_id,
        dot,
        vec![(
            Field::Lifecycle,
            FieldValue::Lifecycle(clavis_core::causal::LifecycleValue::Deleted),
        )],
    )?;
    let (rid, gen) = commit(store, vault, &snapshot, &state.heads, state.generation)?;
    Ok((rid, gen))
}

/// Explicit restore of a deleted entry.
pub fn restore_account(
    store: &Store,
    vault: &UnlockedVault,
    entry_id: EntryId,
    expected_generation: u64,
) -> Result<(RevisionId, u64), CoreError> {
    let state = load_state(store, &vault.vault_id, vault)?;
    if state.generation != expected_generation {
        return Err(CoreError::StaleRevision);
    }
    let mut snapshot = state.snapshot;
    let dot = next_dot(store, &vault.vault_id)?;
    clavis_core::vault::apply_local_action(
        &mut snapshot,
        entry_id,
        dot,
        vec![(
            Field::Lifecycle,
            FieldValue::Lifecycle(clavis_core::causal::LifecycleValue::Active),
        )],
    )?;
    let (rid, gen) = commit(store, vault, &snapshot, &state.heads, state.generation)?;
    Ok((rid, gen))
}

pub fn resolve_conflict(
    store: &Store,
    vault: &UnlockedVault,
    resolution: crate::conflict::Resolution,
    expected_heads: &[RevisionId],
    expected_generation: u64,
) -> Result<(RevisionId, u64), CoreError> {
    let state = load_state(store, &vault.vault_id, vault)?;
    if state.generation != expected_generation {
        return Err(CoreError::StaleRevision);
    }
    let mut sorted_heads = state.heads.clone();
    sorted_heads.sort();
    let mut expected = expected_heads.to_vec();
    expected.sort();
    if sorted_heads != expected {
        // The displayed conflict is stale.
        return Err(CoreError::StaleRevision);
    }
    let mut snapshot = state.snapshot;
    let entry = snapshot
        .accounts
        .get(&resolution.entry_id)
        .ok_or(CoreError::InvalidInput("unknown account"))?;
    let value = entry
        .registers
        .get(&resolution.field)
        .and_then(|r| {
            r.distinct_values()
                .into_iter()
                .nth(resolution.candidate_index)
        })
        .ok_or(CoreError::InvalidInput("candidate index out of range"))?;
    let dot = next_dot(store, &vault.vault_id)?;
    crate::conflict::apply_resolution(&mut snapshot, &resolution, &value, dot)?;
    let (rid, gen) = commit(store, vault, &snapshot, &state.heads, state.generation)?;
    Ok((rid, gen))
}

pub fn keep_both(
    store: &Store,
    vault: &UnlockedVault,
    entry_id: EntryId,
    field: Field,
    keep_original: usize,
    keep_new: usize,
    expected_generation: u64,
) -> Result<(EntryId, RevisionId, u64), CoreError> {
    let state = load_state(store, &vault.vault_id, vault)?;
    if state.generation != expected_generation {
        return Err(CoreError::StaleRevision);
    }
    let mut snapshot = state.snapshot;
    let dot = next_dot(store, &vault.vault_id)?;
    let new_entry_id = EntryId::generate();
    crate::conflict::apply_keep_both(
        &mut snapshot,
        entry_id,
        field,
        keep_original,
        keep_new,
        dot,
        new_entry_id,
    )?;
    let (rid, gen) = commit(store, vault, &snapshot, &state.heads, state.generation)?;
    Ok((new_entry_id, rid, gen))
}

/// Persist a pending outbox entry that failed to upload (durable pending
/// bytes survive process death).
pub fn pending_uploads(
    store: &Store,
    vault_id: &VaultId,
) -> Result<Vec<outbox::OutboxEntry>, CoreError> {
    outbox::pending_entries(store, vault_id)
}
