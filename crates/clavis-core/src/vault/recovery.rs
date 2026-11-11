//! Recovery from an encrypted export with the matching recovery key.
//! Recovery requires an available encrypted copy and its key; it never
//! bypasses provider authentication or recreates deleted data.

use secrecy::SecretString;
use uuid::Uuid;

use crate::causal::Snapshot;
use crate::error::CoreError;
use crate::ids::{RevisionId, VaultId};
use crate::vault::keys::{
    create_vault_with_snapshot, open_container, CreatedVault, UnlockCredential,
};

/// An in-progress recovery: authenticated contents of the export, not yet
/// bound to a new namespace.
pub struct RecoverySession {
    pub source_vault_id: VaultId,
    pub export_id: Uuid,
    pub source_head_ids: Vec<RevisionId>,
    pub snapshot: Snapshot,
}

impl std::fmt::Debug for RecoverySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoverySession({})", self.source_vault_id)
    }
}

/// Open an encrypted export with its matching recovery key. Works on a fresh
/// machine with no provider access; a wrong backup/key pairing fails without
/// producing a vault.
pub fn recover(export_bytes: &[u8], recovery_key: &str) -> Result<RecoverySession, CoreError> {
    let credential = UnlockCredential::RecoveryKey(recovery_key.to_string());
    let (parsed, plaintext, _) = open_container(export_bytes, &credential)?;
    if parsed.header.container_kind.as_deref() != Some("standalone_export") {
        return Err(CoreError::InvalidCredentialOrData);
    }
    let payload: crate::vault::export::ExportPayload =
        serde_json::from_slice(&plaintext).map_err(|_| CoreError::InvalidCredentialOrData)?;
    payload.snapshot.validate()?;
    Ok(RecoverySession {
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

/// Finish recovery: create a fresh namespace (fresh root key, recovery key
/// and passphrase slots) carrying the recovered snapshot. Every standalone
/// restore creates a fresh namespace; it never reattaches a snapshot to the
/// old history or vault ID.
pub fn complete_recovery(
    session: RecoverySession,
    new_passphrase: SecretString,
) -> Result<CreatedVault, CoreError> {
    create_vault_with_snapshot(new_passphrase, session.snapshot, &[])
}
