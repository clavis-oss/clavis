//! Status decision logic. Values exactly match the architecture document;
//! a status must always reflect the actual state truthfully.

use clavis_core::dto::SyncStatusKind;

use crate::engine::SyncReport;

#[derive(Default)]
pub struct SyncContext {
    pub provider_connected: bool,
    pub locked: bool,
    pub offline_hint: bool,
    pub reauth_required: bool,
    pub quota_full: bool,
    pub integrity_error: bool,
    pub migration_required: bool,
    pub has_conflicts: bool,
}

/// Combine a sync report with connection context into a display status.
pub fn decide_status(report: Option<&SyncReport>, ctx: &SyncContext) -> SyncStatusKind {
    if ctx.locked {
        return SyncStatusKind::Locked;
    }
    if ctx.integrity_error {
        return SyncStatusKind::IntegrityError;
    }
    if ctx.migration_required {
        return SyncStatusKind::MigrationRequired;
    }
    if !ctx.provider_connected {
        return SyncStatusKind::LocalOnly;
    }
    if ctx.reauth_required {
        return SyncStatusKind::ReauthRequired;
    }
    if ctx.quota_full {
        return SyncStatusKind::StorageFull;
    }
    if ctx.has_conflicts {
        return SyncStatusKind::Conflict;
    }
    if ctx.offline_hint {
        return SyncStatusKind::Offline;
    }
    match report {
        None => SyncStatusKind::Pending,
        Some(r) => r.status,
    }
}
