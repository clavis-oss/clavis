//! Generated UI DTOs. These types are exported to
//! `packages/contracts/src/generated/` via ts-rs; the UI transports must use
//! them instead of hand-maintained copies. No security implementation lives
//! here and no DTO ever carries a seed or secret.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Sync status values exactly match the architecture document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
#[serde(rename_all = "snake_case")]
pub enum SyncStatusKind {
    LocalOnly,
    Locked,
    Synced,
    Pending,
    Syncing,
    Offline,
    ReauthRequired,
    Conflict,
    StorageFull,
    IntegrityError,
    MigrationRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct CoreErrorDto {
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct AccountSummaryDto {
    pub id: String,
    pub issuer: Option<String>,
    pub account_label: Option<String>,
    pub favorite: bool,
    pub has_conflict: bool,
    pub conflicted_fields: Vec<String>,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct OtpCodeDto {
    pub value: String,
    /// Decimal string; bridges convert to Number only where safe.
    pub valid_until_unix_ms: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct ConflictCandidateDto {
    pub origin: String,
    pub display: String,
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct ConflictDetailDto {
    pub entry_id: String,
    pub field: String,
    pub candidates: Vec<ConflictCandidateDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct ImportPreviewDto {
    /// Opaque preview handle to pass to confirm_import. Expires on
    /// cancel/lock. (Values are small counters, hence number in TS.)
    #[ts(type = "number")]
    pub handle: u64,
    pub issuer: Option<String>,
    pub account_label: Option<String>,
    pub algorithm: String,
    pub digits: u8,
    pub period_seconds: u32,
    pub duplicate_warning: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct VaultInfoDto {
    pub vault_id: String,
    pub name: Option<String>,
    pub provider_kind: Option<String>,
    pub locked: bool,
    pub has_conflicts: bool,
}

/// Manual-entry input for account creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct AccountCodeDto {
    pub account_id: String,
    pub value: String,
    /// Decimal string; bridges convert to Number only where safe.
    pub valid_until_unix_ms: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/contracts/src/generated/")]
pub struct ManualEntryDto {
    pub issuer: String,
    pub account_label: String,
    pub secret_base32: String,
    pub algorithm: String,
    pub digits: u8,
    pub period_seconds: u32,
}
