//! Standalone encrypted export: a portable container, not a plaintext dump
//! and not a remote revision object. The container kind has its own payload
//! domain so revision and export ciphertext can never be confused. It
//! carries the full causal snapshot (contexts, tombstones and unresolved
//! conflict candidates) so backups are lossless.

use serde::{Deserialize, Serialize};

use crate::canonical::base64_url_decode;
use crate::causal::Snapshot;
use crate::error::CoreError;
use crate::ids::{RevisionId, VaultId};
use crate::vault::crypto::{aead_seal, derive_export_payload_key, random_nonce};
use crate::vault::format::{
    parse_container, seal_container, ContainerHeader, RecordKind, EXPORT_MAGIC,
};
use crate::vault::keys::{open_container, slots_for, UnlockCredential, UnlockedVault};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPayload {
    pub snapshot: Snapshot,
}

/// Authenticated export contents after opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportContents {
    pub source_vault_id: VaultId,
    pub export_id: uuid::Uuid,
    pub source_head_ids: Vec<RevisionId>,
    pub snapshot: Snapshot,
}

/// Seal the current snapshot into a standalone encrypted export under the
/// session's wrapping slots. The export is verified by reopening before any
/// caller may report completion.
pub fn seal_export(
    vault: &UnlockedVault,
    snapshot: &Snapshot,
    source_head_ids: &[RevisionId],
) -> Result<Vec<u8>, CoreError> {
    snapshot.validate()?;
    let payload = ExportPayload {
        snapshot: snapshot.clone(),
    };
    let json = serde_json::to_vec(&payload).map_err(|_| CoreError::Internal("export json"))?;
    let mut header = ContainerHeader {
        vault_id: vault.vault_id.0,
        revision_id: uuid::Uuid::new_v4(),
        parent_revision_ids: Vec::new(),
        format: crate::FORMAT_VERSION,
        kdf: vault.kdf.clone(),
        key_slots: slots_for(vault)?,
        payload_nonce: crate::canonical::base64_url_unpadded(&random_nonce()),
        record_kind: RecordKind::Vault,
        container_kind: Some("standalone_export".to_string()),
        source_vault_id: Some(vault.vault_id.0),
        export_id: Some(uuid::Uuid::new_v4()),
        source_head_ids: source_head_ids.iter().map(|r| r.0).collect(),
    };
    header
        .key_slots
        .sort_by_key(|s| matches!(s.kind, crate::vault::format::KeySlotKind::Recovery));
    // Empty-ciphertext probe == exact stored header bytes (no tag).
    let aad = seal_container(EXPORT_MAGIC, &header, &[])?;
    let payload_nonce: [u8; 24] = base64_url_decode(&header.payload_nonce)
        .map_err(|_| CoreError::IntegrityFailure)?
        .try_into()
        .map_err(|_| CoreError::IntegrityFailure)?;
    let key = derive_export_payload_key(vault.root_key(), &vault.vault_id);
    let ct = aead_seal(&key, &payload_nonce, &json, &aad);
    seal_container(EXPORT_MAGIC, &header, &ct)
}
/// Open a standalone export with a passphrase or recovery key. Restoring it
/// always creates a fresh namespace; nothing is reattached to old history.
pub fn open_export(
    bytes: &[u8],
    credential: &UnlockCredential,
) -> Result<ExportContents, CoreError> {
    let (parsed, plaintext, _) = open_container(bytes, credential)?;
    if parsed.magic != *EXPORT_MAGIC
        || parsed.header.container_kind.as_deref() != Some("standalone_export")
    {
        return Err(CoreError::InvalidCredentialOrData);
    }
    let payload: ExportPayload =
        serde_json::from_slice(&plaintext).map_err(|_| CoreError::InvalidCredentialOrData)?;
    payload.snapshot.validate()?;
    Ok(ExportContents {
        source_vault_id: VaultId(
            parsed
                .header
                .source_vault_id
                .ok_or(CoreError::InvalidCredentialOrData)?,
        ),
        export_id: parsed
            .header
            .export_id
            .ok_or(CoreError::InvalidCredentialOrData)?,
        source_head_ids: parsed
            .header
            .source_head_ids
            .iter()
            .map(|u| RevisionId(*u))
            .collect(),
        snapshot: payload.snapshot,
    })
}

/// Convenience wrapper around `parse_container` for callers that only need
/// to know whether bytes are an export container.
pub fn is_export_container(bytes: &[u8]) -> bool {
    parse_container(bytes)
        .map(|p| p.magic == *EXPORT_MAGIC)
        .unwrap_or(false)
}
