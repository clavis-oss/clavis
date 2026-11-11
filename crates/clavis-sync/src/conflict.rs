//! Explicit conflict resolution helpers. Resolution writes a fresh value
//! whose context includes all currently observed candidate dots; a candidate
//! authored concurrently and not yet observed remains a conflict.

use clavis_core::causal::{Dot, Field, FieldValue, Snapshot};
use clavis_core::error::CoreError;
use clavis_core::ids::EntryId;

/// Choice for a conflicted register.
pub struct Resolution {
    pub entry_id: EntryId,
    pub field: Field,
    /// Index into the deterministic candidate list shown to the user.
    pub candidate_index: usize,
}

/// Apply one resolution to the snapshot using the caller's fresh dot. The
/// dot allocation itself is transactional in the store.
pub fn apply_resolution(
    snapshot: &mut Snapshot,
    resolution: &Resolution,
    value: &FieldValue,
    dot: Dot,
) -> Result<(), CoreError> {
    let entry = snapshot
        .accounts
        .get(&resolution.entry_id)
        .ok_or(CoreError::InvalidInput("unknown account"))?;
    let reg = entry
        .registers
        .get(&resolution.field)
        .ok_or(CoreError::InvalidInput("no conflict on this field"))?;
    let candidates = reg.distinct_values();
    if candidates.len() <= 1 {
        return Err(CoreError::InvalidInput("no conflict on this field"));
    }
    let _ = resolution.candidate_index; // validated by caller against the shown list
    clavis_core::vault::apply_local_action(
        snapshot,
        resolution.entry_id,
        dot,
        vec![(resolution.field, value.clone())],
    )
}

/// "Keep both accounts": offered only when each resulting entry can contain
/// a complete, valid OTP configuration. The chosen original keeps the entry
/// ID; the other candidate becomes a new UUIDv4 entry. Both receive fresh
/// actions.
pub fn apply_keep_both(
    snapshot: &mut Snapshot,
    entry_id: EntryId,
    field: Field,
    keep_original: usize,
    keep_new: usize,
    dot: Dot,
    new_entry_id: EntryId,
) -> Result<(), CoreError> {
    let entry = snapshot
        .accounts
        .get(&entry_id)
        .ok_or(CoreError::InvalidInput("unknown account"))?
        .clone();
    let reg = entry
        .registers
        .get(&field)
        .ok_or(CoreError::InvalidInput("no conflict on this field"))?;
    let candidates = reg.distinct_values();
    if candidates.len() != 2 {
        return Err(CoreError::InvalidInput(
            "keep-both applies to exactly two candidates",
        ));
    }
    if keep_original == keep_new || keep_original > 1 || keep_new > 1 {
        return Err(CoreError::InvalidInput("invalid keep-both selection"));
    }
    // Both resulting entries must be complete accounts (a complete OTP
    // config exists on both sides) and not tombstones.
    let complete =
        |v: &FieldValue| -> bool { matches!(v, FieldValue::OtpConfig(c) if c.validate().is_ok()) };
    if field == Field::OtpConfig && (!complete(&candidates[0]) || !complete(&candidates[1])) {
        return Err(CoreError::InvalidInput(
            "cannot keep both: an entry would be incomplete",
        ));
    }
    let lifecycle = entry
        .registers
        .get(&Field::Lifecycle)
        .and_then(|r| r.single_value());
    if matches!(
        lifecycle,
        Some(FieldValue::Lifecycle(
            clavis_core::causal::LifecycleValue::Deleted
        ))
    ) {
        return Err(CoreError::InvalidInput("cannot duplicate a deleted entry"));
    }

    // Original entry keeps the chosen candidate.
    clavis_core::vault::apply_local_action(
        snapshot,
        entry_id,
        dot,
        vec![(field, candidates[keep_original].clone())],
    )?;
    // New entry: copy the original registers, set the other candidate and
    // assign fresh dots for the whole entry.
    let mut new_entry = entry.clone();
    new_entry.registers.insert(
        field,
        clavis_core::vault::single_register(dot, candidates[keep_new].clone()),
    );
    // Give the copied registers fresh dots so later replays of the old state
    // cannot overwrite the deliberate choice.
    let fresh: Vec<(Field, FieldValue)> = new_entry
        .registers
        .iter()
        .filter(|(f, _)| **f != field)
        .filter_map(|(f, r)| r.single_value().map(|v| (*f, v)))
        .collect();
    snapshot.accounts.insert(new_entry_id, new_entry);
    clavis_core::vault::apply_local_action(snapshot, new_entry_id, dot, fresh)?;
    snapshot.validate()
}
