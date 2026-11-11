//! Vault creation, unlocking and revision sealing.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::canonical::base64_url_decode;
use crate::causal::{Field, FieldValue, LifecycleValue, Register, Snapshot};
use crate::error::CoreError;
use crate::ids::{EntryId, RevisionId, VaultId};
use crate::vault::crypto::{
    self, derive_export_payload_key, derive_passphrase_wrap_key, derive_payload_key,
    derive_recovery_wrap_key, encode_recovery_key, random_nonce, slot_aad, RootKey,
    RECOVERY_KEY_LEN, ROOT_KEY_LEN, TAG_LEN,
};
use crate::vault::format::{
    parse_container, seal_container, ContainerHeader, KeySlot, KeySlotKind, ParsedContainer,
    RecordKind, EXPORT_MAGIC, REVISION_MAGIC,
};

/// Wrapped root-key slot bytes carried forward from the container a session
/// was opened with. A session opened via the recovery key does not hold the
/// passphrase wrap key; the existing passphrase slot is copied verbatim into
/// future revisions so both credentials keep working without ever seeing the
/// other secret (and vice versa).
#[derive(Clone, Debug, Default)]
pub struct SlotPassthrough {
    pub passphrase: Option<KeySlot>,
    pub recovery: Option<KeySlot>,
}

/// An unlocked vault session object. Holds the root key and whichever derived
/// wrapping keys were computable at unlock time, in best-effort zeroized
/// buffers. Never serializable; never crosses a process boundary.
#[derive(Clone)]
pub struct UnlockedVault {
    pub vault_id: VaultId,
    root_key: RootKey,
    wrap_passphrase: Option<Zeroizing<[u8; 32]>>,
    wrap_recovery: Option<Zeroizing<[u8; 32]>>,
    passthrough: SlotPassthrough,
    pub kdf: crypto::KdfParams,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnlockedVault({})", self.vault_id)
    }
}

/// A freshly created or restored vault. The recovery key is presented once
/// per session through this handle; there is no later reveal-by-passphrase.
pub struct RecoveryKeyPresentation {
    pub(crate) canonical: String,
    presented: bool,
}

impl RecoveryKeyPresentation {
    pub fn present(&mut self) -> Result<&str, CoreError> {
        if self.presented {
            return Err(CoreError::InvalidInput(
                "recovery key was already presented",
            ));
        }
        self.presented = true;
        Ok(&self.canonical)
    }
    pub fn was_presented(&self) -> bool {
        self.presented
    }
    /// Canonical recovery-key string for the single-session migration flow,
    /// which must hand the new key to the user exactly like fresh creation.
    pub fn canonical_for_session(&self) -> &str {
        &self.canonical
    }
}

impl std::fmt::Debug for RecoveryKeyPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryKeyPresentation([REDACTED])")
    }
}

/// Result of `create_vault`. UI receives the recovery presentation handle,
/// never the root key.
pub struct CreatedVault {
    pub vault_id: VaultId,
    pub revision_id: RevisionId,
    pub unlocked: UnlockedVault,
    pub first_revision: RevisionBlob,
    pub recovery_key: RecoveryKeyPresentation,
}

impl std::fmt::Debug for CreatedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CreatedVault({})", self.vault_id)
    }
}

/// Serialized encrypted revision bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionBlob(pub Vec<u8>);

/// Credential used to unwrap a vault's root key.
#[derive(Clone)]
pub enum UnlockCredential {
    Passphrase(SecretString),
    RecoveryKey(String),
}

fn kind_rank(kind: &KeySlotKind) -> u8 {
    match kind {
        KeySlotKind::Passphrase => 0,
        KeySlotKind::Recovery => 1,
    }
}

fn sorted_parents(parents: &[RevisionId]) -> Vec<Uuid> {
    let mut p: Vec<Uuid> = parents.iter().map(|r| r.0).collect();
    p.sort();
    p.dedup();
    p
}

fn wrap_root_key_slot(
    kind: KeySlotKind,
    wrap_key: &[u8; 32],
    root_key: &RootKey,
    vault_id: VaultId,
    kdf: &crypto::KdfParams,
) -> Result<KeySlot, CoreError> {
    let (domain, kind_str) = match kind {
        KeySlotKind::Passphrase => (crypto::DOMAIN_PASSPHRASE_WRAP, "passphrase"),
        KeySlotKind::Recovery => (crypto::DOMAIN_RECOVERY_WRAP, "recovery"),
    };
    let nonce = random_nonce();
    let aad = slot_aad(domain, kind_str, &vault_id, crate::FORMAT_VERSION, kdf);
    let ct = crypto::aead_seal(wrap_key, &nonce, root_key.bytes(), &aad);
    Ok(KeySlot {
        kind,
        nonce: crate::canonical::base64_url_unpadded(&nonce),
        wrapped_root_key: crate::canonical::base64_url_unpadded(&ct),
    })
}

fn header_base(
    vault_id: VaultId,
    revision_id: RevisionId,
    parents: &[RevisionId],
    kdf: crypto::KdfParams,
    payload_nonce: &[u8; 24],
    record_kind: RecordKind,
) -> ContainerHeader {
    ContainerHeader {
        vault_id: vault_id.0,
        revision_id: revision_id.0,
        parent_revision_ids: sorted_parents(parents),
        format: crate::FORMAT_VERSION,
        kdf,
        key_slots: Vec::new(),
        payload_nonce: crate::canonical::base64_url_unpadded(payload_nonce),
        record_kind,
        container_kind: None,
        source_vault_id: None,
        export_id: None,
        source_head_ids: Vec::new(),
    }
}

pub(crate) fn slots_for(vault: &UnlockedVault) -> Result<Vec<KeySlot>, CoreError> {
    let mut out = Vec::new();
    match (&vault.wrap_passphrase, &vault.passthrough.passphrase) {
        (Some(k), _) => out.push(wrap_root_key_slot(
            KeySlotKind::Passphrase,
            k,
            &vault.root_key,
            vault.vault_id,
            &vault.kdf,
        )?),
        (None, Some(slot)) => out.push(slot.clone()),
        (None, None) => return Err(CoreError::Internal("no passphrase slot available")),
    }
    match (&vault.wrap_recovery, &vault.passthrough.recovery) {
        (Some(k), _) => out.push(wrap_root_key_slot(
            KeySlotKind::Recovery,
            k,
            &vault.root_key,
            vault.vault_id,
            &vault.kdf,
        )?),
        (None, Some(slot)) => out.push(slot.clone()),
        (None, None) => return Err(CoreError::Internal("no recovery slot available")),
    }
    out.sort_by_key(|a| kind_rank(&a.kind));
    Ok(out)
}

/// Payload AAD must be the exact stored header bytes. A probe sealed with
/// empty ciphertext is exactly magic+version+length+header (no tag), so it
/// is used verbatim.
fn payload_aad(magic: &[u8; 4], header: &ContainerHeader) -> Result<Vec<u8>, CoreError> {
    seal_container(magic, header, &[])
}

/// Seal a snapshot into a revision under an unlocked vault. Every revision
/// carries the same passphrase/recovery wrapping slots for the vault
/// namespace and a freshly generated payload nonce.
pub fn seal_revision(
    vault: &UnlockedVault,
    snapshot: &Snapshot,
    parents: &[RevisionId],
) -> Result<RevisionBlob, CoreError> {
    seal_revision_with_kind(vault, snapshot, parents, RecordKind::Vault)
}

pub fn seal_revision_with_kind(
    vault: &UnlockedVault,
    snapshot: &Snapshot,
    parents: &[RevisionId],
    record_kind: RecordKind,
) -> Result<RevisionBlob, CoreError> {
    snapshot.validate()?;
    if parents.len() > crate::vault::format::MAX_PARENTS {
        return Err(CoreError::CapacityReached);
    }
    let revision_id = RevisionId::generate();
    let mut header = header_base(
        vault.vault_id,
        revision_id,
        parents,
        vault.kdf.clone(),
        &random_nonce(),
        record_kind,
    );
    header.key_slots = slots_for(vault)?;
    let payload = serde_json::to_vec(snapshot).map_err(|_| CoreError::Internal("snapshot json"))?;
    let aad = payload_aad(REVISION_MAGIC, &header)?;
    let payload_nonce: [u8; 24] = base64_url_decode(&header.payload_nonce)
        .map_err(|_| CoreError::IntegrityFailure)?
        .try_into()
        .map_err(|_| CoreError::IntegrityFailure)?;
    let payload_key = derive_payload_key(&vault.root_key, &vault.vault_id);
    let ct = crypto::aead_seal(&payload_key, &payload_nonce, &payload, &aad);
    Ok(RevisionBlob(seal_container(REVISION_MAGIC, &header, &ct)?))
}

/// Open a revision or export container with a passphrase or recovery key.
/// Wrong credentials and tampered data are indistinguishable by design and
/// both yield `InvalidCredentialOrData`; they never replace existing data.
pub fn open_container(
    bytes: &[u8],
    credential: &UnlockCredential,
) -> Result<(ParsedContainer, Vec<u8>, RootKey), CoreError> {
    let parsed = parse_container(bytes)?;
    let vault_id = VaultId(parsed.header.vault_id);
    let root_key = match credential {
        UnlockCredential::Passphrase(passphrase) => {
            crypto::check_passphrase_input(passphrase)?;
            let kdf = &parsed.header.kdf;
            let slot = parsed
                .header
                .slot(KeySlotKind::Passphrase)
                .ok_or(CoreError::InvalidCredentialOrData)?;
            let wrap_key = derive_passphrase_wrap_key(passphrase, kdf, &vault_id)?;
            unwrap_root_key(slot, &wrap_key, &vault_id, &parsed.header.kdf)?
        }
        UnlockCredential::RecoveryKey(encoded) => {
            let bytes = crypto::decode_recovery_key(encoded)?;
            let slot = parsed
                .header
                .slot(KeySlotKind::Recovery)
                .ok_or(CoreError::InvalidCredentialOrData)?;
            let wrap_key = derive_recovery_wrap_key(&bytes, &vault_id);
            unwrap_root_key(slot, &wrap_key, &vault_id, &parsed.header.kdf)?
        }
    };
    let payload_key = if parsed.magic == *EXPORT_MAGIC {
        derive_export_payload_key(&root_key, &vault_id)
    } else {
        derive_payload_key(&root_key, &vault_id)
    };
    let nonce: [u8; 24] = base64_url_decode(&parsed.header.payload_nonce)
        .map_err(|_| CoreError::InvalidCredentialOrData)?
        .try_into()
        .map_err(|_| CoreError::InvalidCredentialOrData)?;
    let plaintext = crypto::aead_open(
        &payload_key,
        &nonce,
        &parsed.ciphertext,
        &parsed.stored_header_bytes,
    )?;
    Ok((parsed, plaintext, root_key))
}

fn unwrap_root_key(
    slot: &KeySlot,
    wrap_key: &[u8; 32],
    vault_id: &VaultId,
    kdf: &crypto::KdfParams,
) -> Result<RootKey, CoreError> {
    let nonce: [u8; 24] = base64_url_decode(&slot.nonce)
        .map_err(|_| CoreError::InvalidCredentialOrData)?
        .try_into()
        .map_err(|_| CoreError::InvalidCredentialOrData)?;
    let ct = base64_url_decode(&slot.wrapped_root_key)
        .map_err(|_| CoreError::InvalidCredentialOrData)?;
    if ct.len() != ROOT_KEY_LEN + TAG_LEN {
        return Err(CoreError::InvalidCredentialOrData);
    }
    let (domain, kind_str) = match slot.kind {
        KeySlotKind::Passphrase => (crypto::DOMAIN_PASSPHRASE_WRAP, "passphrase"),
        KeySlotKind::Recovery => (crypto::DOMAIN_RECOVERY_WRAP, "recovery"),
    };
    let aad = slot_aad(domain, kind_str, vault_id, crate::FORMAT_VERSION, kdf);
    let pt = crypto::aead_open(wrap_key, &nonce, &ct, &aad)?;
    let arr: [u8; ROOT_KEY_LEN] = pt
        .try_into()
        .map_err(|_| CoreError::InvalidCredentialOrData)?;
    Ok(RootKey::from_bytes(arr))
}

impl UnlockedVault {
    pub fn root_key(&self) -> &RootKey {
        &self.root_key
    }
}

/// Open a revision with a credential and return its validated snapshot plus
/// an `UnlockedVault` for further sealing in the same namespace.
pub fn open_revision(
    bytes: &[u8],
    credential: &UnlockCredential,
) -> Result<(Snapshot, UnlockedVault, RevisionId), CoreError> {
    let (parsed, plaintext, root_key) = open_container(bytes, credential)?;
    if parsed.magic != *REVISION_MAGIC {
        return Err(CoreError::InvalidCredentialOrData);
    }
    let snapshot: Snapshot =
        serde_json::from_slice(&plaintext).map_err(|_| CoreError::InvalidCredentialOrData)?;
    snapshot.validate()?;
    let vault_id = VaultId(parsed.header.vault_id);
    let wrap_passphrase = match credential {
        UnlockCredential::Passphrase(passphrase) => Some(derive_passphrase_wrap_key(
            passphrase,
            &parsed.header.kdf,
            &vault_id,
        )?),
        UnlockCredential::RecoveryKey(_) => None,
    };
    let wrap_recovery = match credential {
        UnlockCredential::RecoveryKey(encoded) => {
            let bytes = crypto::decode_recovery_key(encoded)?;
            Some(derive_recovery_wrap_key(&bytes, &vault_id))
        }
        UnlockCredential::Passphrase(_) => None,
    };
    let passthrough = SlotPassthrough {
        passphrase: parsed.header.slot(KeySlotKind::Passphrase).cloned(),
        recovery: parsed.header.slot(KeySlotKind::Recovery).cloned(),
    };
    Ok((
        snapshot,
        UnlockedVault {
            vault_id,
            root_key,
            wrap_passphrase,
            wrap_recovery,
            passthrough,
            kdf: parsed.header.kdf.clone(),
        },
        RevisionId(parsed.header.revision_id),
    ))
}

/// Create a fresh vault namespace with a new root key, recovery key and
/// wrapping slots for the given passphrase.
pub fn create_vault(passphrase: SecretString) -> Result<CreatedVault, CoreError> {
    create_vault_with_snapshot(passphrase, Snapshot::new(), &[])
}

/// Create a fresh namespace carrying an existing snapshot (used by export
/// restore and migration). Entry identities and causal state are preserved;
/// keys, salts and nonces are always fresh.
pub fn create_vault_with_snapshot(
    passphrase: SecretString,
    snapshot: Snapshot,
    parents: &[RevisionId],
) -> Result<CreatedVault, CoreError> {
    crypto::check_passphrase_input(&passphrase)?;
    snapshot.validate()?;
    let vault_id = VaultId::generate();
    let kdf = crypto::KdfParams::generate()?;
    let root_key = RootKey::generate();
    let mut recovery_bytes = [0u8; RECOVERY_KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut recovery_bytes);

    let wrap_passphrase = derive_passphrase_wrap_key(&passphrase, &kdf, &vault_id)?;
    let wrap_recovery = derive_recovery_wrap_key(&recovery_bytes, &vault_id);

    let vault = UnlockedVault {
        vault_id,
        root_key,
        wrap_passphrase: Some(wrap_passphrase),
        wrap_recovery: Some(wrap_recovery),
        passthrough: SlotPassthrough::default(),
        kdf,
    };
    let first_revision = seal_revision(&vault, &snapshot, parents)?;

    Ok(CreatedVault {
        vault_id,
        revision_id: revision_id_of(&first_revision)?,
        unlocked: vault,
        first_revision,
        recovery_key: RecoveryKeyPresentation {
            canonical: encode_recovery_key(&recovery_bytes),
            presented: false,
        },
    })
}

pub fn revision_id_of(blob: &RevisionBlob) -> Result<RevisionId, CoreError> {
    let parsed = parse_container(&blob.0)?;
    Ok(RevisionId(parsed.header.revision_id))
}

/// Payload of a revision opened with the root key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenedPayload {
    Snapshot(Snapshot),
    Retirement(RetirementPayload),
}

/// Open a revision using an already-unwrapped root key (no KDF work). Used
/// by the sync engine and the local state loader inside a live session.
pub fn open_revision_with_root(
    bytes: &[u8],
    root_key: &RootKey,
) -> Result<(OpenedPayload, RevisionId), CoreError> {
    let parsed = parse_container(bytes)?;
    let vault_id = VaultId(parsed.header.vault_id);
    if parsed.magic != *REVISION_MAGIC {
        return Err(CoreError::InvalidCredentialOrData);
    }
    let payload_key = derive_payload_key(root_key, &vault_id);
    let nonce: [u8; 24] = base64_url_decode(&parsed.header.payload_nonce)
        .map_err(|_| CoreError::InvalidCredentialOrData)?
        .try_into()
        .map_err(|_| CoreError::InvalidCredentialOrData)?;
    let plaintext = crypto::aead_open(
        &payload_key,
        &nonce,
        &parsed.ciphertext,
        &parsed.stored_header_bytes,
    )?;
    let payload = match parsed.header.record_kind {
        RecordKind::Vault => {
            let snapshot: Snapshot = serde_json::from_slice(&plaintext)
                .map_err(|_| CoreError::InvalidCredentialOrData)?;
            snapshot.validate()?;
            OpenedPayload::Snapshot(snapshot)
        }
        RecordKind::Retirement => OpenedPayload::Retirement(
            serde_json::from_slice(&plaintext).map_err(|_| CoreError::InvalidCredentialOrData)?,
        ),
    };
    Ok((payload, RevisionId(parsed.header.revision_id)))
}

/// Helper: assign registers for a local logical action with a fresh dot.
/// Replaces all observed candidates of each edited register and advances the
/// context. A normal edit of an active entry also re-assigns `active` with
/// the same dot; a delete assigns `deleted`.
pub fn apply_local_action(
    snapshot: &mut Snapshot,
    entry_id: EntryId,
    dot: crate::causal::Dot,
    values: Vec<(Field, FieldValue)>,
) -> Result<(), CoreError> {
    let entry = snapshot.accounts.entry(entry_id).or_default();
    let has_lifecycle_edit = values.iter().any(|(f, _)| *f == Field::Lifecycle);
    let mut edited: Vec<(Field, FieldValue)> = values;
    if !has_lifecycle_edit {
        // Ordinary edit of an active entry also assigns active; this makes a
        // concurrent delete and edit conflict as specified.
        edited.push((
            Field::Lifecycle,
            FieldValue::Lifecycle(LifecycleValue::Active),
        ));
    }
    for (field, value) in edited {
        let reg = entry.registers.entry(field).or_default();
        // Advance the context over all currently observed candidates.
        for (d, _) in &reg.values {
            crate::causal::context_max(&mut reg.context, d.writer, d.counter);
        }
        crate::causal::context_max(&mut reg.context, dot.writer, dot.counter);
        reg.values.clear();
        reg.values.push((dot, value));
    }
    snapshot.validate()
}

/// Tombstone helper for account deletion.
pub fn tombstone_value() -> FieldValue {
    FieldValue::Lifecycle(LifecycleValue::Deleted)
}

/// Retirement payload for a source namespace after migration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetirementPayload {
    pub migration_id: Uuid,
    pub destination_vault_id: Uuid,
    pub included_source_heads: Vec<Uuid>,
}

/// Seal an authenticated retirement revision on the source namespace.
pub fn seal_retirement(
    vault: &UnlockedVault,
    parents: &[RevisionId],
    payload: &RetirementPayload,
) -> Result<RevisionBlob, CoreError> {
    let json = serde_json::to_vec(payload).map_err(|_| CoreError::Internal("retirement json"))?;
    let revision_id = RevisionId::generate();
    let mut header = header_base(
        vault.vault_id,
        revision_id,
        parents,
        vault.kdf.clone(),
        &random_nonce(),
        RecordKind::Retirement,
    );
    header.key_slots = slots_for(vault)?;
    let aad = payload_aad(REVISION_MAGIC, &header)?;
    let payload_nonce: [u8; 24] = base64_url_decode(&header.payload_nonce)
        .map_err(|_| CoreError::IntegrityFailure)?
        .try_into()
        .map_err(|_| CoreError::IntegrityFailure)?;
    let payload_key = derive_payload_key(&vault.root_key, &vault.vault_id);
    let ct = crypto::aead_seal(&payload_key, &payload_nonce, &json, &aad);
    Ok(RevisionBlob(seal_container(REVISION_MAGIC, &header, &ct)?))
}

/// Open a retirement revision (returns its payload).
pub fn open_retirement(
    bytes: &[u8],
    credential: &UnlockCredential,
) -> Result<RetirementPayload, CoreError> {
    let (parsed, plaintext, _) = open_container(bytes, credential)?;
    if parsed.header.record_kind != RecordKind::Retirement {
        return Err(CoreError::InvalidCredentialOrData);
    }
    serde_json::from_slice(&plaintext).map_err(|_| CoreError::InvalidCredentialOrData)
}

/// Create a register with a single value from a fresh dot (import helpers).
pub fn single_register(dot: crate::causal::Dot, value: FieldValue) -> Register {
    let mut r = Register::default();
    r.values.push((dot, value));
    r.context.push((dot.writer, dot.counter));
    r
}
