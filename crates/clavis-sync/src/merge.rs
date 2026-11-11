//! Register merge over validated, authenticated snapshots. Deterministic:
//! merge results are independent of delivery order and idempotent.

use clavis_core::causal::Snapshot;
use clavis_core::error::CoreError;
use clavis_core::ids::RevisionId;
use clavis_core::vault::crypto::RootKey;
use clavis_core::vault::keys::{open_revision_with_root, OpenedPayload};

use crate::graph::ValidatedGraph;

pub struct MergeResult {
    pub snapshot: Snapshot,
    pub heads: Vec<RevisionId>,
    pub has_conflicts: bool,
    pub retirement: Option<clavis_core::vault::keys::RetirementPayload>,
}

/// Merge all validated revisions of a graph. Requires the root key (from a
/// live unlocked session) to open payload snapshots.
pub fn merge_heads(graph: &ValidatedGraph, root_key: &RootKey) -> Result<MergeResult, CoreError> {
    let mut merged = Snapshot::new();
    let mut retirement = None;
    // Topological order is irrelevant for the CRDT merge; iterate sorted for
    // determinism of any error surface.
    for (rid, node) in &graph.nodes {
        let (payload, check_id) = open_revision_with_root(&node.blob, root_key)?;
        if check_id != *rid {
            return Err(CoreError::IntegrityFailure);
        }
        match payload {
            OpenedPayload::Snapshot(s) => {
                merged = merged.merge(&s)?;
            }
            OpenedPayload::Retirement(r) => {
                retirement = Some(r);
            }
        }
    }
    let has_conflicts = !clavis_core::accounts::list_conflicts(&merged).is_empty();
    Ok(MergeResult {
        snapshot: merged,
        heads: graph.heads.clone(),
        has_conflicts,
        retirement,
    })
}
