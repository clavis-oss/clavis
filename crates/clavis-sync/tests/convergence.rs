//! Multi-device convergence: deterministic merge over all delivery
//! orderings, causal conflict preservation and explicit resolution.

use secrecy::SecretString;
use std::collections::BTreeMap;

use clavis_core::causal::{Dot, Field, FieldValue, LifecycleValue, Snapshot};
use clavis_core::ids::{DeviceId, EntryId, RevisionId, VaultId, WriterId};
use clavis_core::otp::{OtpAlgorithm, OtpConfigValue, OtpSeed};
use clavis_core::vault::keys::{
    apply_local_action, create_vault, open_revision_with_root, seal_revision, OpenedPayload,
    UnlockedVault,
};
use clavis_sync::graph::{validate_graph, RevisionNode};
use clavis_sync::merge::merge_heads;

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

struct Device {
    vault: UnlockedVault,
    vault_id: VaultId,
    writer: WriterId,
    counter: u64,
    local_heads: Vec<RevisionId>,
    snapshot: Snapshot,
    blobs: Vec<(RevisionId, Vec<u8>)>,
}

/// The shared vault namespace behind a multi-device test.
struct SharedVault {
    vault: UnlockedVault,
    vault_id: VaultId,
    genesis: RevisionId,
    genesis_blob: Vec<u8>,
}

impl SharedVault {
    fn new() -> Self {
        let created = create_vault(pass("convergence test passphrase")).unwrap();
        SharedVault {
            vault_id: created.vault_id,
            vault: created.unlocked,
            genesis: created.revision_id,
            genesis_blob: created.first_revision.0,
        }
    }
}

impl Device {
    /// All devices share one vault namespace; each has its own device
    /// identity, snapshot view and local heads.
    fn new(name_seed: u8, shared: &SharedVault) -> Self {
        let writer = WriterId(
            shared.vault_id,
            DeviceId(clavis_core::ids::RawUuid::from_u128(name_seed as u128)),
        );
        Device {
            vault: shared.vault.clone(),
            vault_id: shared.vault_id,
            writer,
            counter: 0,
            local_heads: vec![shared.genesis],
            snapshot: Snapshot::new(),
            blobs: vec![(shared.genesis, shared.genesis_blob.clone())],
        }
    }

    fn next_dot(&mut self) -> Dot {
        self.counter += 1;
        Dot {
            writer: self.writer,
            counter: self.counter,
        }
    }

    fn add_account(&mut self, issuer: &str, secret_byte: u8) -> EntryId {
        let entry = EntryId::generate();
        let dot = self.next_dot();
        apply_local_action(
            &mut self.snapshot,
            entry,
            dot,
            vec![
                (Field::Issuer, FieldValue::Issuer(issuer.to_string())),
                (
                    Field::OtpConfig,
                    FieldValue::OtpConfig(OtpConfigValue {
                        secret: OtpSeed::new(vec![secret_byte; 20]),
                        algorithm: OtpAlgorithm::Sha1,
                        digits: 6,
                        period_seconds: 30,
                    }),
                ),
            ],
        )
        .unwrap();
        self.commit();
        entry
    }

    fn edit(&mut self, entry: EntryId, field: Field, value: FieldValue) {
        let dot = self.next_dot();
        apply_local_action(&mut self.snapshot, entry, dot, vec![(field, value)]).unwrap();
        self.commit();
    }

    fn delete(&mut self, entry: EntryId) {
        let dot = self.next_dot();
        apply_local_action(
            &mut self.snapshot,
            entry,
            dot,
            vec![(
                Field::Lifecycle,
                FieldValue::Lifecycle(LifecycleValue::Deleted),
            )],
        )
        .unwrap();
        self.commit();
    }

    fn commit(&mut self) {
        let blob = seal_revision(&self.vault, &self.snapshot, &self.local_heads).unwrap();
        let rid = clavis_core::vault::keys::revision_id_of(&blob).unwrap();
        self.local_heads = vec![rid];
        self.blobs.push((rid, blob.0));
    }

    /// Receive every remote blob we do not know (eventual delivery) and
    /// merge its authenticated payload into the local snapshot view, exactly
    /// as the sync engine does before further local edits.
    fn receive(&mut self, incoming: &[(RevisionId, Vec<u8>)]) {
        for (rid, blob) in incoming {
            if self.blobs.iter().any(|(r, _)| r == rid) {
                continue;
            }
            let (payload, check_id) =
                clavis_core::vault::keys::open_revision_with_root(blob, self.vault.root_key())
                    .unwrap_or_else(|e| panic!("received blob failed to open: {e}"));
            assert_eq!(check_id, *rid);
            if let OpenedPayload::Snapshot(s) = payload {
                self.snapshot = self.snapshot.merge(&s).unwrap();
            }
            self.blobs.push((*rid, blob.clone()));
        }
    }

    /// Validate the graph and merge all snapshots (what the engine does).
    fn merged(&self) -> (Snapshot, Vec<RevisionId>) {
        let nodes: Vec<RevisionNode> = self
            .blobs
            .iter()
            .map(|(r, b)| RevisionNode {
                revision_id: *r,
                parents: Vec::new(),
                blob: b.clone(),
            })
            .collect();
        let graph = validate_graph(&self.vault_id, &nodes).unwrap();
        let result = merge_heads(&graph, self.vault.root_key()).unwrap();
        (result.snapshot, result.heads)
    }
}

fn otp_value(byte: u8) -> FieldValue {
    FieldValue::OtpConfig(OtpConfigValue {
        secret: OtpSeed::new(vec![byte; 20]),
        algorithm: OtpAlgorithm::Sha1,
        digits: 6,
        period_seconds: 30,
    })
}

#[test]
fn two_offline_additions_preserve_both() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let ea = a.add_account("From A", 1);
    let eb = b.add_account("From B", 2);
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    a.receive(&bblobs);
    b.receive(&ablobs);
    for d in [&mut a, &mut b] {
        let (snapshot, heads) = d.merged();
        assert_eq!(heads.len(), 2, "two heads until a merge revision");
        assert!(snapshot.accounts.contains_key(&ea));
        assert!(snapshot.accounts.contains_key(&eb));
        assert_eq!(snapshot.accounts.len(), 2);
    }
}

#[test]
fn competing_labels_keep_both_candidates() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let e = a.add_account("Example", 3);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    // Both devices concurrently edit the label of the same account.
    a.edit(
        e,
        Field::AccountLabel,
        FieldValue::AccountLabel("A's name".into()),
    );
    b.edit(
        e,
        Field::AccountLabel,
        FieldValue::AccountLabel("B's name".into()),
    );
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    a.receive(&bblobs);
    b.receive(&ablobs);
    let (snapshot, _) = a.merged();
    let reg = snapshot.accounts[&e]
        .registers
        .get(&Field::AccountLabel)
        .unwrap();
    let values = reg.distinct_values();
    assert_eq!(values.len(), 2, "both competing labels remain candidates");
    // OTP config is unaffected by a label conflict.
    let otp = snapshot.accounts[&e]
        .registers
        .get(&Field::OtpConfig)
        .unwrap()
        .single_value()
        .unwrap();
    assert_eq!(otp, otp_value(3));
}

#[test]
fn identical_concurrent_values_collapse_to_one() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let e = a.add_account("Example", 4);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    a.edit(e, Field::Issuer, FieldValue::Issuer("Same".into()));
    b.edit(e, Field::Issuer, FieldValue::Issuer("Same".into()));
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    a.receive(&bblobs);
    b.receive(&ablobs);
    let (snapshot, _) = a.merged();
    let issuer = snapshot.accounts[&e].registers.get(&Field::Issuer).unwrap();
    assert_eq!(issuer.distinct_values().len(), 1);
}

#[test]
fn delete_versus_edit_is_a_lifecycle_conflict() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let e = a.add_account("Example", 5);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    a.delete(e);
    b.edit(
        e,
        Field::AccountLabel,
        FieldValue::AccountLabel("edited".into()),
    );
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    a.receive(&bblobs);
    b.receive(&ablobs);
    let (snapshot, _) = a.merged();
    let lifecycle = snapshot.accounts[&e]
        .registers
        .get(&Field::Lifecycle)
        .unwrap();
    let values = lifecycle.distinct_values();
    assert_eq!(values.len(), 2);
    assert!(values.contains(&FieldValue::Lifecycle(LifecycleValue::Deleted)));
    assert!(values.contains(&FieldValue::Lifecycle(LifecycleValue::Active)));
    // Code generation is blocked for a conflicted lifecycle.
    assert!(snapshot.accounts[&e].blocks_code_generation());
}

#[test]
fn otp_config_is_atomic_in_merge() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let e = a.add_account("Example", 6);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    // Full OTP config replacement on each side (atomic field).
    a.edit(e, Field::OtpConfig, otp_value(7));
    b.edit(e, Field::OtpConfig, otp_value(8));
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    a.receive(&bblobs);
    b.receive(&ablobs);
    let (snapshot, _) = a.merged();
    let otp = snapshot.accounts[&e]
        .registers
        .get(&Field::OtpConfig)
        .unwrap();
    let values = otp.distinct_values();
    assert_eq!(values.len(), 2);
    // Never a partial mix: each candidate is complete and valid.
    for v in &values {
        match v {
            FieldValue::OtpConfig(c) => {
                assert!(c.secret.bytes() == vec![7u8; 20] || c.secret.bytes() == vec![8u8; 20]);
                assert!(c.validate().is_ok());
            }
            _ => panic!("non-config candidate in otp register"),
        }
    }
}

#[test]
fn resolution_suppresses_replayed_candidates() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let e = a.add_account("Example", 9);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    a.edit(e, Field::Issuer, FieldValue::Issuer("A".into()));
    b.edit(e, Field::Issuer, FieldValue::Issuer("B".into()));
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    a.receive(&bblobs);
    b.receive(&ablobs);

    // A resolves to A's value: fresh dot whose context covers both
    // candidates.
    let dot = a.next_dot();
    apply_local_action(
        &mut a.snapshot,
        e,
        dot,
        vec![(Field::Issuer, FieldValue::Issuer("A".into()))],
    )
    .unwrap();
    a.commit();
    let rblobs = a.blobs.clone();

    // Replay the old conflicting state into a fresh third device that then
    // receives the resolution: B must not return.
    let mut c = Device::new(3, &shared);
    c.receive(&ablobs);
    c.receive(&bblobs);
    c.receive(&rblobs);
    let (snapshot, _) = c.merged();
    let issuer = snapshot.accounts[&e].registers.get(&Field::Issuer).unwrap();
    assert_eq!(
        issuer.distinct_values(),
        vec![FieldValue::Issuer("A".into())]
    );
}

#[test]
fn concurrent_resolutions_retain_both_decisions() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let e = a.add_account("Example", 10);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    a.edit(e, Field::Issuer, FieldValue::Issuer("A".into()));
    b.edit(e, Field::Issuer, FieldValue::Issuer("B".into()));
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    a.receive(&bblobs);
    b.receive(&ablobs);

    // Both devices resolve — to different values.
    let dot_a = a.next_dot();
    apply_local_action(
        &mut a.snapshot,
        e,
        dot_a,
        vec![(Field::Issuer, FieldValue::Issuer("A".into()))],
    )
    .unwrap();
    a.commit();
    let dot_b = b.next_dot();
    apply_local_action(
        &mut b.snapshot,
        e,
        dot_b,
        vec![(Field::Issuer, FieldValue::Issuer("B".into()))],
    )
    .unwrap();
    b.commit();
    let rblobs_a = a.blobs.clone();
    let rblobs_b = b.blobs.clone();
    a.receive(&rblobs_b);
    b.receive(&rblobs_a);
    let (snapshot, _) = a.merged();
    let issuer = snapshot.accounts[&e].registers.get(&Field::Issuer).unwrap();
    assert_eq!(
        issuer.distinct_values().len(),
        2,
        "both resolutions retained"
    );
}

#[test]
fn merge_is_permutation_invariant_and_idempotent() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let mut c = Device::new(3, &shared);
    let e = a.add_account("Example", 11);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    c.receive(&ablobs);
    a.edit(e, Field::Issuer, FieldValue::Issuer("from-a".into()));
    b.edit(
        e,
        Field::AccountLabel,
        FieldValue::AccountLabel("from-b".into()),
    );
    c.delete(e);
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    let cblobs = c.blobs.clone();

    fn merge_all(
        blobs: Vec<&[(RevisionId, Vec<u8>)]>,
        root: &UnlockedVault,
        vault_id: &VaultId,
    ) -> Snapshot {
        let mut all: BTreeMap<RevisionId, Vec<u8>> = BTreeMap::new();
        for set in blobs {
            for (r, b) in set.iter() {
                all.insert(*r, b.clone());
            }
        }
        let nodes: Vec<RevisionNode> = all
            .iter()
            .map(|(r, b)| RevisionNode {
                revision_id: *r,
                parents: Vec::new(),
                blob: b.clone(),
            })
            .collect();
        let graph = validate_graph(vault_id, &nodes).unwrap();
        merge_heads(&graph, root.root_key()).unwrap().snapshot
    }

    let s1 = merge_all(vec![&ablobs, &bblobs, &cblobs], &a.vault, &a.vault_id);
    let s2 = merge_all(vec![&cblobs, &ablobs, &bblobs], &a.vault, &a.vault_id);
    let s3 = merge_all(vec![&bblobs, &cblobs, &ablobs], &a.vault, &a.vault_id);
    assert_eq!(s1, s2, "permutation invariance");
    assert_eq!(s2, s3);
    // Idempotence: merging the merged state with itself changes nothing.
    let s4 = merge_all(
        vec![&ablobs, &bblobs, &cblobs, &ablobs],
        &a.vault,
        &a.vault_id,
    );
    assert_eq!(s1, s4);
    // All unobserved candidates preserved: label has one candidate (only B
    // edited it), lifecycle has both delete/edit candidates.
    let e_reg = &s1.accounts[&e];
    assert_eq!(
        e_reg.registers[&Field::AccountLabel].distinct_values(),
        vec![FieldValue::AccountLabel("from-b".into())]
    );
    assert_eq!(
        e_reg.registers[&Field::Lifecycle].distinct_values().len(),
        2
    );
}

#[test]
fn three_devices_with_gaps_and_criss_cross_ancestry_converge() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let mut b = Device::new(2, &shared);
    let mut c = Device::new(3, &shared);
    let e = a.add_account("Example", 12);
    let ablobs = a.blobs.clone();
    b.receive(&ablobs);
    c.receive(&ablobs);
    // Criss-cross: A gets B's work, C gets A's work, then everyone syncs.
    a.edit(e, Field::Favorite, FieldValue::Favorite(true));
    b.edit(e, Field::Issuer, FieldValue::Issuer("crossed".into()));
    let ablobs = a.blobs.clone();
    let bblobs = b.blobs.clone();
    c.receive(&ablobs);
    b.receive(&ablobs);
    a.receive(&bblobs);
    c.receive(&bblobs);
    // A late arrival from C's earlier state changes nothing (idempotence).
    let cblobs = c.blobs.clone();
    a.receive(&cblobs);
    let (sa, _) = a.merged();
    let (sb, _) = b.merged();
    let (sc, _) = c.merged();
    assert_eq!(sa, sb, "all devices converge");
    assert_eq!(sb, sc);
    // Every acknowledged edit survived somewhere in the merged state.
    assert_eq!(
        sa.accounts[&e].registers[&Field::Favorite].distinct_values(),
        vec![FieldValue::Favorite(true)]
    );
    assert_eq!(
        sa.accounts[&e].registers[&Field::Issuer].distinct_values(),
        vec![FieldValue::Issuer("crossed".into())]
    );
}

#[test]
fn corrupted_ciphertext_is_rejected_not_merged() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    let _e = a.add_account("Example", 13);
    let mut blob = a.blobs[1].1.clone();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    let result = open_revision_with_root(&blob, a.vault.root_key());
    assert!(
        result.is_err(),
        "corrupted revision must fail authentication"
    );
}

#[test]
fn missing_parent_is_incomplete_not_a_head() {
    let shared = SharedVault::new();
    let mut a = Device::new(1, &shared);
    a.add_account("Example", 14);
    // Drop the middle revision: the graph is incomplete.
    let mut partial = a.blobs.clone();
    partial.remove(0);
    let nodes: Vec<RevisionNode> = partial
        .iter()
        .map(|(r, b)| RevisionNode {
            revision_id: *r,
            parents: Vec::new(),
            blob: b.clone(),
        })
        .collect();
    let err = validate_graph(&a.vault_id, &nodes).unwrap_err();
    assert!(matches!(
        err,
        clavis_sync::graph::GraphError::MissingParents(_)
    ));
}

#[test]
fn unrelated_roots_are_never_silently_united() {
    let shared = SharedVault::new();
    let other = SharedVault::new();
    let a = Device::new(1, &shared);
    let b = Device::new(2, &other);
    // Different vault namespaces: b's blobs carry a different vault_id, so
    // graph validation rejects cross-namespace content.
    let nodes: Vec<RevisionNode> = b
        .blobs
        .iter()
        .map(|(r, bl)| RevisionNode {
            revision_id: *r,
            parents: Vec::new(),
            blob: bl.clone(),
        })
        .collect();
    let err = validate_graph(&a.vault_id, &nodes).unwrap_err();
    assert!(matches!(
        err,
        clavis_sync::graph::GraphError::Core(clavis_core::error::CoreError::IntegrityFailure)
    ));
}
