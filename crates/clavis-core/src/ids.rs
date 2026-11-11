use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use uuid::Uuid as RawUuid;

/// Random UUIDv4 vault identity. Vault namespaces are isolated; revision
/// graph parents never cross a vault boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VaultId(pub Uuid);

/// Random UUIDv4 revision identity within a vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RevisionId(pub Uuid);

/// Random UUIDv4 entry identity. Local entry identity is immutable and
/// survives edits, sync and migrations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryId(pub Uuid);

/// Random UUIDv4 device identity used in operation dots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

/// Operation-dot writer: `(origin_vault_id, device_id)`. Imported/migrated
/// dots retain their origin vault so provenance is transitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WriterId(pub VaultId, pub DeviceId);

impl VaultId {
    pub fn generate() -> Self {
        VaultId(Uuid::new_v4())
    }
    pub fn as_bytes(&self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl RevisionId {
    pub fn generate() -> Self {
        RevisionId(Uuid::new_v4())
    }
    pub fn as_bytes(&self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl EntryId {
    pub fn generate() -> Self {
        EntryId(Uuid::new_v4())
    }
}

impl DeviceId {
    pub fn generate() -> Self {
        DeviceId(Uuid::new_v4())
    }
}

impl std::fmt::Display for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::fmt::Display for RevisionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
