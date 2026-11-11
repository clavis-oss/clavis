//! Account views over causal snapshots: safe summaries without seeds,
//! conflict detection and code generation gating.

use crate::causal::{AccountEntry, Field, FieldValue, LifecycleValue, Register, Snapshot};
use crate::error::CoreError;
use crate::ids::EntryId;
use crate::otp::{OtpConfig, OtpConfigValue, OtpSeed};

/// Safe display DTO: ID, issuer, account label, favorite and conflict flags.
/// It has no seed and never exposes one.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountSummary {
    pub id: EntryId,
    pub issuer: Option<String>,
    pub account_label: Option<String>,
    pub favorite: bool,
    pub has_conflict: bool,
    pub conflicted_fields: Vec<Field>,
    pub deleted: bool,
}

fn field_string(reg: Option<&Register>) -> Option<String> {
    match reg.and_then(Register::single_value) {
        Some(FieldValue::Issuer(s)) | Some(FieldValue::AccountLabel(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Summaries for the account list. Tombstoned entries are included with
/// `deleted: true` only when requested by callers; the default excludes them.
pub fn list_summaries(snapshot: &Snapshot) -> Vec<AccountSummary> {
    let mut out: Vec<AccountSummary> = snapshot
        .accounts
        .iter()
        .map(|(id, entry)| summary_for(*id, entry))
        .collect();
    out.sort_by(|a, b| {
        let ai = (a.issuer.clone(), a.account_label.clone());
        let bi = (b.issuer.clone(), b.account_label.clone());
        ai.cmp(&bi).then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn summary_for(id: EntryId, entry: &AccountEntry) -> AccountSummary {
    let favorite = matches!(
        entry
            .registers
            .get(&Field::Favorite)
            .and_then(Register::single_value),
        Some(FieldValue::Favorite(true))
    );
    let deleted = matches!(
        entry
            .registers
            .get(&Field::Lifecycle)
            .and_then(Register::single_value),
        Some(FieldValue::Lifecycle(LifecycleValue::Deleted))
    );
    let conflicted = entry.conflicted_fields();
    AccountSummary {
        id,
        issuer: field_string(entry.registers.get(&Field::Issuer)),
        account_label: field_string(entry.registers.get(&Field::AccountLabel)),
        favorite,
        has_conflict: !conflicted.is_empty(),
        conflicted_fields: conflicted,
        deleted,
    }
}

/// The single OTP configuration of an entry, or an error when the entry is
/// conflicted (codes must never be generated from conflicted configuration)
/// or tombstoned.
pub fn otp_config_for(snapshot: &Snapshot, entry_id: EntryId) -> Result<OtpConfigValue, CoreError> {
    let entry = snapshot
        .accounts
        .get(&entry_id)
        .ok_or(CoreError::InvalidInput("unknown account"))?;
    let lifecycle = entry
        .registers
        .get(&Field::Lifecycle)
        .and_then(Register::single_value);
    match lifecycle {
        Some(FieldValue::Lifecycle(LifecycleValue::Deleted)) => {
            return Err(CoreError::InvalidInput("account is deleted"));
        }
        Some(FieldValue::Lifecycle(LifecycleValue::Active)) => {}
        _ if entry
            .registers
            .get(&Field::Lifecycle)
            .map(Register::is_conflicted)
            .unwrap_or(false) =>
        {
            return Err(CoreError::InvalidInput("account lifecycle is conflicted"));
        }
        _ => {}
    }
    let reg = entry
        .registers
        .get(&Field::OtpConfig)
        .ok_or(CoreError::InvalidInput("account has no OTP configuration"))?;
    let single = reg.single_value().ok_or(CoreError::InvalidInput(
        "account OTP configuration is conflicted",
    ))?;
    match single {
        FieldValue::OtpConfig(cfg) => {
            cfg.validate()?;
            Ok(cfg.clone())
        }
        _ => Err(CoreError::IntegrityFailure),
    }
}

pub fn to_otp_config(value: &OtpConfigValue) -> OtpConfig {
    OtpConfig {
        seed: OtpSeed::new(value.secret.bytes().to_vec()),
        algorithm: value.algorithm,
        digits: value.digits,
        period_seconds: value.period_seconds,
    }
}

/// A competing candidate shown to the user during conflict resolution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConflictCandidate {
    /// Origin writer of the candidate dot, displayed as a device identity.
    pub origin: String,
    /// Masked description; candidates never reveal seeds.
    pub display: String,
    /// Selectable index within the candidate list (deterministic order).
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConflictDetail {
    pub entry_id: EntryId,
    pub field: Field,
    pub candidates: Vec<ConflictCandidate>,
}

pub fn field_display(value: &FieldValue) -> String {
    match value {
        FieldValue::Issuer(s) | FieldValue::AccountLabel(s) => s.clone(),
        FieldValue::Favorite(b) => b.to_string(),
        FieldValue::OtpConfig(cfg) => format!(
            "OTP · {:?} · {} digits · {}s",
            cfg.algorithm, cfg.digits, cfg.period_seconds
        ),
        FieldValue::Lifecycle(l) => format!("{l:?}"),
    }
}

/// All unresolved conflicts in a snapshot, deterministically ordered.
pub fn list_conflicts(snapshot: &Snapshot) -> Vec<ConflictDetail> {
    let mut out = Vec::new();
    for (id, entry) in &snapshot.accounts {
        for (field, reg) in &entry.registers {
            if !reg.is_conflicted() {
                continue;
            }
            let candidates = reg
                .distinct_values()
                .iter()
                .enumerate()
                .map(|(i, v)| ConflictCandidate {
                    origin: origin_of(reg, v),
                    display: field_display(v),
                    index: i as u32,
                })
                .collect();
            out.push(ConflictDetail {
                entry_id: *id,
                field: *field,
                candidates,
            });
        }
    }
    out
}

fn origin_of(reg: &Register, value: &FieldValue) -> String {
    for (dot, v) in &reg.values {
        if v == value {
            return format!("{} · #{}", dot.writer.0 .0, dot.writer.1 .0);
        }
    }
    "unknown".to_string()
}
