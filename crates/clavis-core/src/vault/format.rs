//! `clavis-v1` wire format: bounded header parsing and serialization.
//!
//! Wire layout (revision objects, magic `CLVS`; standalone exports, `CLVX`):
//! `magic(4) | u16le format(2) | u32le header_len(4) | header JSON | ciphertext+tag`
//!
//! Limits are enforced before any allocation or KDF work: header <= 16 KiB,
//! whole object <= 8 MiB, duplicate JSON fields rejected.

use std::io::Write;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::canonical::reject_duplicate_json_fields;
use crate::error::CoreError;
use crate::vault::crypto::KdfParams;

pub const REVISION_MAGIC: &[u8; 4] = b"CLVS";
pub const EXPORT_MAGIC: &[u8; 4] = b"CLVX";
pub const MAX_HEADER_LEN: usize = 16 * 1024;
pub const MAX_OBJECT_LEN: usize = 8 * 1024 * 1024;
pub const MAX_PARENTS: usize = 256;
/// Passphrase input limit (UTF-8 bytes, exact bytes preserved).
pub const MAX_PASSPHRASE_LEN: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Vault,
    Retirement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySlotKind {
    Passphrase,
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySlot {
    pub kind: KeySlotKind,
    /// Base64url 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Base64url wrapped root key (32 bytes + tag).
    pub wrapped_root_key: String,
}

/// Authenticated container header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContainerHeader {
    pub vault_id: Uuid,
    pub revision_id: Uuid,
    #[serde(default)]
    pub parent_revision_ids: Vec<Uuid>,
    pub format: u16,
    pub kdf: KdfParams,
    pub key_slots: Vec<KeySlot>,
    pub payload_nonce: String,
    #[serde(default = "default_record_kind")]
    pub record_kind: RecordKind,
    // Standalone export container fields (magic CLVX).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_vault_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_head_ids: Vec<Uuid>,
}

fn default_record_kind() -> RecordKind {
    RecordKind::Vault
}

pub struct ParsedContainer {
    pub magic: [u8; 4],
    pub header: ContainerHeader,
    /// Exact stored bytes of magic+version+len+header; the payload AAD.
    pub stored_header_bytes: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Parse and bound-check a container without doing any cryptographic work.
pub fn parse_container(bytes: &[u8]) -> Result<ParsedContainer, CoreError> {
    if bytes.len() > MAX_OBJECT_LEN {
        return Err(CoreError::ResourceLimit);
    }
    if bytes.len() < 4 + 2 + 4 {
        return Err(CoreError::InvalidCredentialOrData);
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if magic != *REVISION_MAGIC && magic != *EXPORT_MAGIC {
        return Err(CoreError::UnsupportedFormat);
    }
    let format = u16::from_le_bytes([bytes[4], bytes[5]]);
    if format != crate::FORMAT_VERSION {
        return Err(CoreError::UnsupportedFormat);
    }
    let header_len = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(CoreError::ResourceLimit);
    }
    let header_start = 4 + 2 + 4;
    if bytes.len() < header_start + header_len {
        return Err(CoreError::InvalidCredentialOrData);
    }
    let header_json = &bytes[header_start..header_start + header_len];
    let ciphertext_start = header_start + header_len;
    let ciphertext = bytes[ciphertext_start..].to_vec();
    if ciphertext.len() < 16 {
        // Truncated authentication tag.
        return Err(CoreError::InvalidCredentialOrData);
    }
    reject_duplicate_json_fields(header_json)?;
    let header: ContainerHeader =
        serde_json::from_slice(header_json).map_err(|_| CoreError::UnsupportedFormat)?;
    header.validate()?;
    let mut stored_header_bytes = Vec::with_capacity(header_start + header_len);
    stored_header_bytes
        .write_all(&bytes[..header_start + header_len])
        .expect("preallocated exact size");
    Ok(ParsedContainer {
        magic,
        header,
        stored_header_bytes,
        ciphertext,
    })
}

impl ContainerHeader {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.format != crate::FORMAT_VERSION {
            return Err(CoreError::UnsupportedFormat);
        }
        if self.kdf.validate().is_err() {
            return Err(CoreError::ResourceLimit);
        }
        if self.key_slots.len() > 4 || self.key_slots.is_empty() {
            return Err(CoreError::InvalidCredentialOrData);
        }
        for slot in &self.key_slots {
            if slot.nonce.len() != 32 || slot.wrapped_root_key.len() != 64 {
                // base64url lengths: 24 bytes -> 32 chars, 48 bytes -> 64 chars.
                return Err(CoreError::InvalidCredentialOrData);
            }
        }
        if self.payload_nonce.len() != 32 {
            return Err(CoreError::InvalidCredentialOrData);
        }
        if self.parent_revision_ids.len() > MAX_PARENTS {
            return Err(CoreError::CapacityReached);
        }
        let mut sorted = self.parent_revision_ids.clone();
        sorted.sort();
        if sorted != self.parent_revision_ids {
            return Err(CoreError::IntegrityFailure);
        }
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err(CoreError::IntegrityFailure);
        }
        if self.container_kind.is_some() {
            if self.container_kind.as_deref() != Some("standalone_export") {
                return Err(CoreError::UnsupportedFormat);
            }
            if self.source_vault_id.is_none() || self.export_id.is_none() {
                return Err(CoreError::InvalidCredentialOrData);
            }
        }
        Ok(())
    }

    pub fn slot(&self, kind: KeySlotKind) -> Option<&KeySlot> {
        self.key_slots.iter().find(|s| s.kind == kind)
    }
}

/// Serialize a header and ciphertext into the wire format for `magic`.
pub fn seal_container(
    magic: &[u8; 4],
    header: &ContainerHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let header_json = serde_json::to_vec(header).map_err(|_| CoreError::Internal("header json"))?;
    if header_json.len() > MAX_HEADER_LEN {
        return Err(CoreError::ResourceLimit);
    }
    let total = 4 + 2 + 4 + header_json.len() + ciphertext.len();
    if total > MAX_OBJECT_LEN {
        return Err(CoreError::ResourceLimit);
    }
    let mut out = Vec::with_capacity(total);
    out.write_all(magic).expect("fixed write");
    out.write_all(&crate::FORMAT_VERSION.to_le_bytes())
        .expect("fixed write");
    out.write_all(&(header_json.len() as u32).to_le_bytes())
        .expect("fixed write");
    out.write_all(&header_json).expect("fixed write");
    out.write_all(ciphertext).expect("fixed write");
    Ok(out)
}
