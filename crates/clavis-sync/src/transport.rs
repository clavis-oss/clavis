//! Transport contract: paginated discovery, byte-verified immutable objects.
//! Providers implement these four operations; object paths are
//! `clavis/<vault_id>/revisions/<revision_id>.clv` (Google uses equivalent
//! folder/file IDs). Remote index/head pointers may accelerate discovery but
//! are never authoritative.

use async_trait::async_trait;
use clavis_core::error::CoreError;
use clavis_core::ids::{RevisionId, VaultId};

/// SHA-256 digest of revision bytes.
pub type Digest = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteObject {
    /// Opaque provider locator (file ID, item ID or path). Never persisted
    /// inside vault data.
    pub locator: String,
    pub revision_id: RevisionId,
    pub size: u64,
    pub digest: Option<Digest>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub objects: Vec<RemoteObject>,
    /// Opaque continuation cursor.
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadReceipt {
    pub locator: String,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    #[error("storage is unreachable")]
    Offline,
    #[error("reauthorization required")]
    Unauthorized,
    #[error("storage quota exceeded")]
    QuotaExceeded,
    #[error("rate limited")]
    RateLimited {
        retry_after: Option<std::time::Duration>,
    },
    #[error("remote data failed integrity validation")]
    IntegrityFailure,
    #[error("canceled")]
    Canceled,
    #[error("{0}")]
    OtherSanitized(&'static str),
}

impl SyncError {
    pub fn kind(&self) -> &'static str {
        match self {
            SyncError::Offline => "offline",
            SyncError::Unauthorized => "unauthorized",
            SyncError::QuotaExceeded => "quota_exceeded",
            SyncError::RateLimited { .. } => "rate_limited",
            SyncError::IntegrityFailure => "integrity_failure",
            SyncError::Canceled => "canceled",
            SyncError::OtherSanitized(_) => "other",
        }
    }

    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            SyncError::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }
}

impl From<CoreError> for SyncError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::IntegrityFailure | CoreError::CapacityReached => SyncError::IntegrityFailure,
            CoreError::Canceled => SyncError::Canceled,
            CoreError::ResourceLimit => SyncError::OtherSanitized("object size limit exceeded"),
            _ => SyncError::OtherSanitized("storage operation failed"),
        }
    }
}

pub fn digest(bytes: &[u8]) -> Digest {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// The provider-independent transport. All methods are async; providers must
/// implement pagination, byte verification and idempotent creation.
#[async_trait]
pub trait RemoteStore: Send + Sync {
    async fn list_page(&self, vault_id: &VaultId, cursor: Option<&str>) -> Result<Page, SyncError>;

    async fn get_object(&self, locator: &str) -> Result<Vec<u8>, SyncError>;

    /// Create is idempotent by logical revision ID and verified bytes; a
    /// conflicting different-byte object with the same identity is an
    /// integrity error, never an overwrite.
    async fn create_object(
        &self,
        vault_id: &VaultId,
        revision_id: &RevisionId,
        bytes: Vec<u8>,
    ) -> Result<UploadReceipt, SyncError>;

    async fn verify_object(
        &self,
        receipt: &UploadReceipt,
        expected: &Digest,
    ) -> Result<(), SyncError> {
        if receipt.digest != *expected {
            return Err(SyncError::IntegrityFailure);
        }
        Ok(())
    }
}

/// Logical object key for a revision.
pub fn object_key(vault_id: &VaultId, revision_id: &RevisionId) -> String {
    format!("clavis/{}/revisions/{}.clv", vault_id, revision_id)
}
