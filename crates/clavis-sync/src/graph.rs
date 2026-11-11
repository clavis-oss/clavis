//! Revision graph validation. Ancestry is verified independently of the
//! register merge: cycles, cross-vault parents, impossible limits and
//! authenticated-parent inconsistencies are rejected before any state is
//! merged. A missing parent during eventual listing is reported as an
//! incomplete sync, never resolved by taking an arbitrary head.

use std::collections::{BTreeMap, BTreeSet};

use clavis_core::error::CoreError;
use clavis_core::ids::{RevisionId, VaultId};
use clavis_core::vault::format::parse_container;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionNode {
    pub revision_id: RevisionId,
    pub parents: Vec<RevisionId>,
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGraph {
    pub nodes: BTreeMap<RevisionId, RevisionNode>,
    pub heads: Vec<RevisionId>,
    pub retirement_revisions: Vec<RevisionId>,
}

pub const MAX_NODES: usize = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("incomplete sync: {0} missing parents")]
    MissingParents(usize),
    #[error(transparent)]
    Core(#[from] CoreError),
}

/// Validate a set of revision blobs for one vault namespace. Each blob's
/// authenticated header must belong to the namespace; parents must resolve
/// within the node set.
pub fn validate_graph(
    vault_id: &VaultId,
    nodes: &[RevisionNode],
) -> Result<ValidatedGraph, GraphError> {
    if nodes.len() > MAX_NODES {
        return Err(CoreError::CapacityReached.into());
    }
    let mut map: BTreeMap<RevisionId, RevisionNode> = BTreeMap::new();
    let mut children: BTreeMap<RevisionId, usize> = BTreeMap::new();
    let mut retirement = Vec::new();
    for node in nodes {
        let parsed = parse_container(&node.blob)?;
        if VaultId(parsed.header.vault_id) != *vault_id {
            // Cross-vault parents/objects are an integrity error.
            return Err(CoreError::IntegrityFailure.into());
        }
        let rid = RevisionId(parsed.header.revision_id);
        if rid != node.revision_id {
            return Err(CoreError::IntegrityFailure.into());
        }
        if map
            .insert(
                rid,
                RevisionNode {
                    revision_id: rid,
                    parents: parsed
                        .header
                        .parent_revision_ids
                        .iter()
                        .map(|u| RevisionId(*u))
                        .collect(),
                    blob: node.blob.clone(),
                },
            )
            .is_some()
        {
            // Byte-identical duplicates were deduped earlier; a second node
            // with the same ID here implies different bytes.
            return Err(CoreError::IntegrityFailure.into());
        }
        if parsed.header.record_kind == clavis_core::vault::format::RecordKind::Retirement {
            retirement.push(rid);
        }
        for p in &parsed.header.parent_revision_ids {
            *children.entry(RevisionId(*p)).or_insert(0) += 1;
        }
    }
    // Missing parents: retried as incomplete sync, never guessed around.
    let missing = map
        .keys()
        .flat_map(|r| map[r].parents.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|p| !map.contains_key(p))
        .count();
    if missing > 0 {
        return Err(GraphError::MissingParents(missing));
    }
    // Cycle detection via Kahn's algorithm over parent→child edges.
    let mut indegree: BTreeMap<RevisionId, usize> =
        map.iter().map(|(r, n)| (*r, n.parents.len())).collect();
    let mut children_of: BTreeMap<RevisionId, Vec<RevisionId>> = BTreeMap::new();
    for (r, n) in &map {
        for p in &n.parents {
            children_of.entry(*p).or_default().push(*r);
        }
    }
    let mut queue: Vec<RevisionId> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(r, _)| *r)
        .collect();
    let mut seen = 0;
    while let Some(r) = queue.pop() {
        seen += 1;
        for c in children_of.get(&r).into_iter().flatten() {
            let d = indegree.get_mut(c).unwrap();
            *d -= 1;
            if *d == 0 {
                queue.push(*c);
            }
        }
    }
    if seen != map.len() {
        return Err(CoreError::IntegrityFailure.into());
    }
    let heads: Vec<RevisionId> = map
        .keys()
        .copied()
        .filter(|r| !children.contains_key(r))
        .collect();
    Ok(ValidatedGraph {
        nodes: map,
        heads,
        retirement_revisions: retirement,
    })
}
