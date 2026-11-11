//! Causal account state: observed-remove multi-value registers per account
//! field, exactly as specified in the causal protocol document. Merge must be
//! commutative, associative and idempotent for valid states. Timestamps never
//! choose winners.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::ids::{EntryId, WriterId};
use crate::otp::OtpConfigValue;

/// Account field set. The complete OTP configuration is one atomic
/// `otp_config` value; lifecycle carries `active`/`deleted`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Issuer,
    AccountLabel,
    Favorite,
    OtpConfig,
    Lifecycle,
}

impl Field {
    pub fn name(&self) -> &'static str {
        match self {
            Field::Issuer => "issuer",
            Field::AccountLabel => "account_label",
            Field::Favorite => "favorite",
            Field::OtpConfig => "otp_config",
            Field::Lifecycle => "lifecycle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleValue {
    Active,
    Deleted,
}

/// A candidate value for a register field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldValue {
    Issuer(String),
    AccountLabel(String),
    Favorite(bool),
    OtpConfig(OtpConfigValue),
    Lifecycle(LifecycleValue),
}

impl FieldValue {
    pub fn field(&self) -> Field {
        match self {
            FieldValue::Issuer(_) => Field::Issuer,
            FieldValue::AccountLabel(_) => Field::AccountLabel,
            FieldValue::Favorite(_) => Field::Favorite,
            FieldValue::OtpConfig(_) => Field::OtpConfig,
            FieldValue::Lifecycle(_) => Field::Lifecycle,
        }
    }
}

/// Operation dot `(origin_vault_id, device_id, counter)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Dot {
    pub writer: WriterId,
    pub counter: u64,
}

/// Version vector keyed by writer. Stored as a sequence so JSON round
/// trips keep struct keys intact; contexts are small (bounded by the
/// freeze-gate writer limit).
pub type VersionVector = Vec<(WriterId, u64)>;

pub fn context_sees(context: &VersionVector, dot: &Dot) -> bool {
    context
        .iter()
        .any(|(w, c)| *w == dot.writer && *c >= dot.counter)
}

pub fn context_max(context: &mut VersionVector, writer: WriterId, counter: u64) {
    if let Some(entry) = context.iter_mut().find(|(w, _)| *w == writer) {
        entry.1 = entry.1.max(counter);
    } else {
        context.push((writer, counter));
    }
}

/// Per-field observed-remove multi-value register.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    pub context: VersionVector,
    /// Live candidates as (dot, value) pairs. A field/dot pair carries one
    /// value; duplicates are an integrity error.
    pub values: Vec<(Dot, FieldValue)>,
}

// `Eq` on FieldValue requires structural equality only; String/bool/OtpConfig
// compare structurally, which is what the merge rules need.
impl Register {
    /// Merge two registers per the causal protocol. Duplicate dot with a
    /// different value is an integrity error.
    pub fn merge(&self, other: &Register) -> Result<Register, CoreError> {
        let mut values: Vec<(Dot, FieldValue)> = Vec::new();
        for (dot, v) in &self.values {
            match other.values.iter().find(|(d, _)| d == dot) {
                Some((_, v2)) if v2 == v => values.push((*dot, v.clone())),
                Some(_) => return Err(CoreError::IntegrityFailure),
                None => {
                    if !context_sees(&other.context, dot) {
                        values.push((*dot, v.clone()));
                    }
                }
            }
        }
        for (dot, v) in &other.values {
            if !values.iter().any(|(d, _)| d == dot) && !context_sees(&self.context, dot) {
                values.push((*dot, v.clone()));
            }
        }
        let mut context: VersionVector = self.context.clone();
        for (w, c) in &other.context {
            context_max(&mut context, *w, *c);
        }
        // Canonical order so merged registers compare equal regardless of
        // delivery order (permutation invariance).
        context.sort();
        values.sort_by_key(|a| a.0);
        Ok(Register { context, values })
    }

    /// Distinct live values in deterministic order (dedupe identical values
    /// that arrived from different dots).
    pub fn distinct_values(&self) -> Vec<FieldValue> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for (_, v) in &self.values {
            let key = serde_json::to_string(v).unwrap_or_default();
            if seen.insert(key) {
                out.push(v.clone());
            }
        }
        out
    }

    pub fn is_conflicted(&self) -> bool {
        self.distinct_values().len() > 1
    }

    /// The single live value, if the register is unambiguous.
    pub fn single_value(&self) -> Option<FieldValue> {
        let d = self.distinct_values();
        if d.len() == 1 {
            Some(d[0].clone())
        } else {
            None
        }
    }
}

/// One account entry: immutable entry identity plus its registers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub registers: BTreeMap<Field, Register>,
}

impl AccountEntry {
    pub fn register(&self, field: Field) -> Option<&Register> {
        self.registers.get(&field)
    }

    pub fn is_tombstoned(&self) -> bool {
        matches!(
            self.registers
                .get(&Field::Lifecycle)
                .and_then(Register::single_value),
            Some(FieldValue::Lifecycle(LifecycleValue::Deleted))
        )
    }

    /// A conflict in OTP configuration or lifecycle state blocks code
    /// generation for the entry; label conflicts do not.
    pub fn blocks_code_generation(&self) -> bool {
        self.registers
            .get(&Field::OtpConfig)
            .map(Register::is_conflicted)
            .unwrap_or(false)
            || self
                .registers
                .get(&Field::Lifecycle)
                .map(Register::is_conflicted)
                .unwrap_or(false)
    }

    pub fn conflicted_fields(&self) -> Vec<Field> {
        self.registers
            .iter()
            .filter(|(_, r)| r.is_conflicted())
            .map(|(f, _)| *f)
            .collect()
    }
}

/// Full causal snapshot carried inside an encrypted revision payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub snapshot_version: u32,
    pub accounts: BTreeMap<EntryId, AccountEntry>,
}

pub const SNAPSHOT_VERSION: u32 = 1;
/// Reader/creation limits from the freeze gate (causal protocol section 5).
pub const MAX_ACCOUNTS: usize = 2_000;
pub const MAX_CANDIDATES_PER_FIELD: usize = 32;
pub const MAX_WRITERS_PER_CONTEXT: usize = 256;

impl Snapshot {
    pub fn new() -> Self {
        Snapshot {
            snapshot_version: SNAPSHOT_VERSION,
            accounts: BTreeMap::new(),
        }
    }

    /// Structural validation before any state is merged.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.snapshot_version != SNAPSHOT_VERSION {
            return Err(CoreError::UnsupportedFormat);
        }
        if self.accounts.len() > MAX_ACCOUNTS {
            return Err(CoreError::CapacityReached);
        }
        for entry in self.accounts.values() {
            for (field, register) in &entry.registers {
                if register.values.len() > MAX_CANDIDATES_PER_FIELD {
                    return Err(CoreError::CapacityReached);
                }
                if register.context.len() > MAX_WRITERS_PER_CONTEXT {
                    return Err(CoreError::CapacityReached);
                }
                if register.context.is_empty() && !register.values.is_empty() {
                    return Err(CoreError::IntegrityFailure);
                }
                for (dot, value) in &register.values {
                    if dot.counter == 0 {
                        return Err(CoreError::IntegrityFailure);
                    }
                    if value.field() != *field {
                        return Err(CoreError::IntegrityFailure);
                    }
                    // Every candidate dot must be covered by the context.
                    if !context_sees(&register.context, dot) {
                        return Err(CoreError::IntegrityFailure);
                    }
                }
                // Duplicate dot with different value within one register is
                // an integrity error.
                for (i, (d1, v1)) in register.values.iter().enumerate() {
                    for (d2, v2) in register.values.iter().skip(i + 1) {
                        if d1 == d2 && v1 != v2 {
                            return Err(CoreError::IntegrityFailure);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Merge another snapshot's register state into this one. Entries and
    /// fields absent on either side are carried. Used by the sync engine for
    /// validated, authenticated states only.
    pub fn merge(&self, other: &Snapshot) -> Result<Snapshot, CoreError> {
        if self.snapshot_version != other.snapshot_version {
            return Err(CoreError::UnsupportedFormat);
        }
        let mut accounts = self.accounts.clone();
        for (id, entry) in &other.accounts {
            match accounts.get_mut(id) {
                Some(mine) => {
                    let mut registers = mine.registers.clone();
                    for (field, reg) in &entry.registers {
                        match registers.get_mut(field) {
                            Some(mine_reg) => {
                                let merged = mine_reg.merge(reg)?;
                                registers.insert(*field, merged);
                            }
                            None => {
                                registers.insert(*field, reg.clone());
                            }
                        }
                    }
                    accounts.insert(*id, AccountEntry { registers });
                }
                None => {
                    accounts.insert(*id, entry.clone());
                }
            }
        }
        let merged = Snapshot {
            snapshot_version: self.snapshot_version,
            accounts,
        };
        merged.validate()?;
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{DeviceId, VaultId};

    fn writer(n: u8) -> WriterId {
        WriterId(
            VaultId(crate::ids::RawUuid::from_u128(n as u128)),
            DeviceId(crate::ids::RawUuid::from_u128((n as u128) + 1000)),
        )
    }

    fn dot(n: u8, counter: u64) -> Dot {
        Dot {
            writer: writer(n),
            counter,
        }
    }

    fn reg(pairs: &[(Dot, FieldValue)]) -> Register {
        let mut r = Register::default();
        for (d, v) in pairs {
            r.values.push((*d, v.clone()));
            context_max(&mut r.context, d.writer, d.counter);
        }
        r
    }

    #[test]
    fn merge_is_commutative_idempotent_and_preserves_concurrent_candidates() {
        let a = reg(&[(dot(1, 1), FieldValue::Issuer("A".into()))]);
        let b = reg(&[(dot(2, 1), FieldValue::Issuer("B".into()))]);
        let ab = a.merge(&b).unwrap();
        let ba = b.merge(&a).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.merge(&ab).unwrap(), ab);
        assert_eq!(ab.distinct_values().len(), 2);
    }

    #[test]
    fn observed_value_is_removed_by_context() {
        let a = reg(&[(dot(1, 1), FieldValue::Issuer("A".into()))]);
        // B observed A's dot and replaced it.
        let mut b = reg(&[(dot(2, 1), FieldValue::Issuer("B".into()))]);
        context_max(&mut b.context, dot(1, 1).writer, 1);
        let merged = a.merge(&b).unwrap();
        assert_eq!(
            merged.distinct_values(),
            vec![FieldValue::Issuer("B".into())]
        );
    }

    #[test]
    fn duplicate_dot_with_different_value_is_integrity_error() {
        let a = reg(&[(dot(1, 1), FieldValue::Issuer("A".into()))]);
        let b = reg(&[(dot(1, 1), FieldValue::Issuer("B".into()))]);
        assert_eq!(a.merge(&b).unwrap_err(), CoreError::IntegrityFailure);
    }

    #[test]
    fn validation_requires_context_coverage() {
        let mut s = Snapshot::new();
        let mut entry = AccountEntry::default();
        let mut r = Register::default();
        r.values.push((dot(1, 1), FieldValue::Issuer("A".into())));
        entry.registers.insert(Field::Issuer, r);
        s.accounts.insert(EntryId::generate(), entry);
        assert_eq!(s.validate().unwrap_err(), CoreError::IntegrityFailure);
    }
}
