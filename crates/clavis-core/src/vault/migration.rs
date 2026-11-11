//! Safe credential/provider migration. V1 has one safe operation:
//! decrypt the source; build a fresh namespace with a new vault ID, root
//! key, passphrase and recovery key; preserve OTP entry IDs and content;
//! save and verify the destination; produce a fresh export; and only after
//! explicit confirmation record the retirement revision and activate.
//! A crash before final activation leaves the source usable.

use secrecy::SecretString;
use uuid::Uuid;

use crate::causal::Snapshot;
use crate::error::CoreError;
use crate::ids::{RevisionId, VaultId};
use crate::vault::export::{open_export, seal_export};
use crate::vault::keys::{
    create_vault_with_snapshot, open_revision, seal_retirement, RevisionBlob, UnlockCredential,
    UnlockedVault,
};

/// Migration journal states (see the causal protocol document, section 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    Prepared,
    Copying,
    Verified,
    SourceCheck,
    RetirementRecorded,
    Activated,
    Completed,
}

/// A prepared but not yet activated migration draft. Cancellation before
/// retirement discards the draft and keeps the source active.
pub struct MigrationDraft {
    pub migration_id: Uuid,
    pub source_vault_id: VaultId,
    pub included_source_heads: Vec<RevisionId>,
    pub destination_vault_id: VaultId,
    pub destination_revision: RevisionBlob,
    /// One-session presentation of the destination recovery key.
    pub destination_recovery_key: String,
    pub export_blob: Vec<u8>,
}

impl std::fmt::Debug for MigrationDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MigrationDraft({} -> {})",
            self.source_vault_id, self.destination_vault_id
        )
    }
}

/// Build a destination namespace from the source snapshot, seal its first
/// revision and a fresh verified export. Plaintext exists only inside this
/// unlocked native process.
pub fn prepare_migration(
    source: &UnlockedVault,
    source_snapshot: &Snapshot,
    source_heads: &[RevisionId],
    new_passphrase: SecretString,
) -> Result<MigrationDraft, CoreError> {
    source_snapshot.validate()?;
    let created = create_vault_with_snapshot(new_passphrase, source_snapshot.clone(), &[])?;
    let export_blob = seal_export(&created.unlocked, source_snapshot, &[])?;
    Ok(MigrationDraft {
        migration_id: Uuid::new_v4(),
        source_vault_id: source.vault_id,
        included_source_heads: source_heads.to_vec(),
        destination_vault_id: created.vault_id,
        destination_revision: created.first_revision,
        destination_recovery_key: created.recovery_key.canonical,
        export_blob,
    })
}

/// Independently reopen the destination revision and export and compare the
/// complete content (including contexts) with the source. No activation
/// happens if this fails.
pub fn verify_destination(
    draft: &MigrationDraft,
    destination_passphrase: &SecretString,
) -> Result<Snapshot, CoreError> {
    let credential = UnlockCredential::Passphrase(destination_passphrase.clone());
    let (snapshot, _vault, _) = open_revision(&draft.destination_revision.0, &credential)?;
    let export = open_export(&draft.export_blob, &credential)?;
    if export.snapshot != snapshot {
        return Err(CoreError::IntegrityFailure);
    }
    if export.source_vault_id != draft.destination_vault_id {
        return Err(CoreError::IntegrityFailure);
    }
    Ok(snapshot)
}

/// Record the authenticated retirement revision on the source namespace.
/// This is the point of no return and requires explicit user confirmation;
/// callers must gate it on a final user decision.
pub fn record_retirement(
    source: &UnlockedVault,
    draft: &MigrationDraft,
    source_heads: &[RevisionId],
) -> Result<RevisionBlob, CoreError> {
    let payload = crate::vault::keys::RetirementPayload {
        migration_id: draft.migration_id,
        destination_vault_id: draft.destination_vault_id.0,
        included_source_heads: source_heads.iter().map(|r| r.0).collect(),
    };
    seal_retirement(source, source_heads, &payload)
}
