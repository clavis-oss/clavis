use thiserror::Error;

/// Core error surface. Messages are safe for display; never include seeds,
/// passphrases, tokens or raw provider responses.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("vault is locked")]
    Locked,
    #[error("could not unlock this vault. Check your passphrase or try a backup.")]
    InvalidCredentialOrData,
    #[error("this vault format is not supported by this version")]
    UnsupportedFormat,
    #[error("the requested resource exceeds a documented limit")]
    ResourceLimit,
    #[error("this change is based on an older revision; reload and reapply")]
    StaleRevision,
    #[error("local storage failed")]
    StorageFailure,
    #[error("the operation was canceled")]
    Canceled,
    #[error("the vault data failed integrity validation")]
    IntegrityFailure,
    #[error("sync is incomplete: remote revisions are still missing")]
    IncompleteSync,
    #[error("capacity reached; the last valid state was preserved")]
    CapacityReached,
    #[error("{0}")]
    InvalidInput(&'static str),
    #[error("{0}")]
    Internal(&'static str),
}

impl CoreError {
    /// Stable machine-readable kind used by UI transports and the CLI.
    pub fn kind(&self) -> &'static str {
        match self {
            CoreError::Locked => "locked",
            CoreError::InvalidCredentialOrData => "invalid_credential_or_data",
            CoreError::UnsupportedFormat => "unsupported_format",
            CoreError::ResourceLimit => "resource_limit",
            CoreError::StaleRevision => "stale_revision",
            CoreError::StorageFailure => "storage_failure",
            CoreError::Canceled => "canceled",
            CoreError::IntegrityFailure => "integrity_failure",
            CoreError::IncompleteSync => "incomplete_sync",
            CoreError::CapacityReached => "capacity_reached",
            CoreError::InvalidInput(_) => "invalid_input",
            CoreError::Internal(_) => "internal",
        }
    }
}
