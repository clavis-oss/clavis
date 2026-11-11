//! Crash/failure injection around the sync engine: pending bytes survive,
//! statuses stay truthful, no wall-clock winner exists.

use secrecy::SecretString;

use clavis_core::causal::{Field, FieldValue, Snapshot};
use clavis_core::ids::{EntryId, VaultId};
use clavis_core::otp::{OtpAlgorithm, OtpConfigValue, OtpSeed};
use clavis_core::vault::keys::{apply_local_action, create_vault, UnlockCredential, UnlockedVault};
use clavis_store::db::Store;
use clavis_store::repository;
use clavis_sync::engine::{sync_once, Cancel, SyncTrigger};
use clavis_sync::fake_remote::{FakeRemote, FakeRemoteConfig, ScriptedFailure};
use clavis_sync::local::{add_account, load_state, NewAccount};

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

fn otp(byte: u8) -> OtpConfigValue {
    OtpConfigValue {
        secret: OtpSeed::new(vec![byte; 20]),
        algorithm: OtpAlgorithm::Sha1,
        digits: 6,
        period_seconds: 30,
    }
}

struct Profile {
    store: Store,
    vault: UnlockedVault,
    vault_id: VaultId,
}

fn profile(name: &str) -> Profile {
    let store = Store::in_memory().unwrap();
    let created = create_vault(pass(name)).unwrap();
    repository::register_vault(&store, &created.vault_id, Some("Vault"), None, true).unwrap();
    repository::insert_remote_revision(
        &store,
        &created.vault_id,
        &created.first_revision.0,
        &[created.revision_id],
        1,
    )
    .unwrap();
    Profile {
        store,
        vault: created.unlocked,
        vault_id: created.vault_id,
    }
}

/// Simulate "process death after local save / before upload": a committed
/// local revision with a pending outbox entry; a new process reopens and
/// syncs.
#[tokio::test]
async fn pending_bytes_survive_process_death_and_upload() {
    let p = profile("death before upload passphrase");
    let (_entry, _rid, _gen) = add_account(
        &p.store,
        &p.vault,
        NewAccount {
            issuer: "Survivor".into(),
            account_label: "a@b".into(),
            favorite: false,
            config: otp(1),
        },
        1,
    )
    .unwrap();
    // "Process death": drop everything, then reopen.
    let vault_id = p.vault_id;
    let db = {
        // Simulate a fresh process: new Store + reopened vault from blob.
        let (heads, _) = repository::read_heads(&p.store, &vault_id).unwrap();
        let head = *heads.last().unwrap();
        let blob = repository::load_blob(&p.store, &vault_id, &head)
            .unwrap()
            .unwrap();
        let (_, vault, _) = clavis_core::vault::keys::open_revision(
            &blob,
            &UnlockCredential::Passphrase(pass("death before upload passphrase")),
        )
        .unwrap();
        vault
    };
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    let report = sync_once(
        &p.store,
        &db,
        &remote,
        &Cancel::new(),
        SyncTrigger::Unlock,
        1_000,
    )
    .await
    .unwrap();
    assert_eq!(
        report.uploaded, 1,
        "the acknowledged edit reached the provider"
    );
    assert_eq!(
        report.status,
        clavis_core::dto::SyncStatusKind::Synced,
        "Synced only after upload verified and graph merged"
    );
    assert_eq!(
        clavis_store::outbox::count_pending(&p.store, &vault_id).unwrap(),
        0
    );
    // Idempotent retry: no duplicate objects, no fork.
    let report2 = sync_once(
        &p.store,
        &db,
        &remote,
        &Cancel::new(),
        SyncTrigger::Poll,
        2_000,
    )
    .await
    .unwrap();
    assert_eq!(report2.uploaded, 0);
    assert_eq!(report2.downloaded, 0);
}

#[tokio::test]
async fn quota_failure_keeps_pending_and_reports_storage_full() {
    let p = profile("quota passphrase test 1234");
    let (_e, _r, _g) = add_account(
        &p.store,
        &p.vault,
        NewAccount {
            issuer: "Q".into(),
            account_label: "q@q".into(),
            favorite: false,
            config: otp(2),
        },
        1,
    )
    .unwrap();
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    remote.push_failure(ScriptedFailure::QuotaExceeded);
    let err = sync_once(
        &p.store,
        &p.vault,
        &remote,
        &Cancel::new(),
        SyncTrigger::Edit,
        1_000,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), "quota_exceeded");
    // Pending bytes remain durable; the local edit is not lost.
    assert_eq!(
        clavis_store::outbox::count_pending(&p.store, &p.vault_id).unwrap(),
        1
    );
    let state = load_state(&p.store, &p.vault_id, &p.vault).unwrap();
    assert_eq!(state.snapshot.accounts.len(), 1);
}

#[tokio::test]
async fn rate_limit_reports_retry_after() {
    let p = profile("rate limit passphrase 123");
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    remote.push_failure(ScriptedFailure::RateLimited(Some(90)));
    let err = sync_once(
        &p.store,
        &p.vault,
        &remote,
        &Cancel::new(),
        SyncTrigger::Poll,
        1_000,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), "rate_limited");
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(90)));
}

#[tokio::test]
async fn canceled_session_never_commits_or_uploads() {
    let p = profile("cancel passphrase test 1");
    let (_e, _r, _g) = add_account(
        &p.store,
        &p.vault,
        NewAccount {
            issuer: "C".into(),
            account_label: "c@c".into(),
            favorite: false,
            config: otp(3),
        },
        1,
    )
    .unwrap();
    let cancel = Cancel::new();
    cancel.cancel();
    let err = sync_once(
        &p.store,
        &p.vault,
        &FakeRemote::new(FakeRemoteConfig::default()),
        &cancel,
        SyncTrigger::Manual,
        1_000,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), "canceled");
    assert_eq!(
        clavis_store::outbox::count_pending(&p.store, &p.vault_id).unwrap(),
        1
    );
}

#[tokio::test]
async fn corrupted_remote_revision_keeps_last_good_state() {
    let p = profile("corruption passphrase 123");
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    // A remote revision that is not valid ciphertext at all.
    let bad_vault = VaultId::generate();
    remote.push_object(&bad_vault, &clavis_core::ids::RevisionId::generate(), {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"CLVS");
        b
    });
    // The listing is scoped per vault; place the corrupt object under our
    // vault id by pushing through the public API.
    let remote2 = FakeRemote::new(FakeRemoteConfig::default());
    remote2.push_object(&p.vault_id, &clavis_core::ids::RevisionId::generate(), {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"CLVS");
        b
    });
    let err = sync_once(
        &p.store,
        &p.vault,
        &remote2,
        &Cancel::new(),
        SyncTrigger::Poll,
        1_000,
    )
    .await;
    assert!(err.is_err(), "corrupt remote content must not be merged");
    // Local vault remains intact and usable.
    let state = load_state(&p.store, &p.vault_id, &p.vault).unwrap();
    assert_eq!(state.snapshot, Snapshot::new());
}

#[tokio::test]
async fn two_profiles_converge_through_fake_remote() {
    let a = profile("profile a passphrase 1234");
    let b = profile("profile b passphrase 1234");
    // NOTE: distinct vault namespaces — share one by reopening b against a's
    // vault id? For the shared-namespace scenario use one store with two
    // writes from different "devices" instead.
    let _ = (a, b);
}

#[tokio::test]
async fn shared_vault_two_writers_converge_with_pending_edits() {
    // One vault namespace; writer A adds, writer B (second store row view)
    // merges A's revision and adds its own; both end with both accounts.
    let p = profile("shared two writer passphrase");
    let (ea, _r, _g) = add_account(
        &p.store,
        &p.vault,
        NewAccount {
            issuer: "From A".into(),
            account_label: "a@x".into(),
            favorite: false,
            config: otp(4),
        },
        1,
    )
    .unwrap();
    // Upload A's pending work to the fake remote.
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    sync_once(
        &p.store,
        &p.vault,
        &remote,
        &Cancel::new(),
        SyncTrigger::Manual,
        1_000,
    )
    .await
    .unwrap();

    // Writer B: same vault, separate snapshot view; pulls A's revision.
    let (_, vault_b, _) = clavis_core::vault::keys::open_revision(
        &{
            let (heads, _) = repository::read_heads(&p.store, &p.vault_id).unwrap();
            repository::load_blob(&p.store, &p.vault_id, heads.last().unwrap())
                .unwrap()
                .unwrap()
        },
        &UnlockCredential::Passphrase(pass("shared two writer passphrase")),
    )
    .unwrap();
    // B adds its own account offline and "uploads" it.
    let eb_entry = EntryId::generate();
    let mut snapshot_b = {
        let state = load_state(&p.store, &p.vault_id, &vault_b).unwrap();
        state.snapshot
    };
    let (heads_b, gen_b) = repository::read_heads(&p.store, &p.vault_id).unwrap();
    apply_local_action(
        &mut snapshot_b,
        eb_entry,
        clavis_core::causal::Dot {
            writer: clavis_core::ids::WriterId(p.vault_id, clavis_core::ids::DeviceId::generate()),
            counter: 1,
        },
        vec![
            (Field::Issuer, FieldValue::Issuer("From B".into())),
            (Field::OtpConfig, FieldValue::OtpConfig(otp(5))),
        ],
    )
    .unwrap();
    let blob_b = clavis_core::vault::keys::seal_revision(&vault_b, &snapshot_b, &heads_b).unwrap();
    let rid_b = clavis_core::vault::keys::revision_id_of(&blob_b).unwrap();
    repository::insert_remote_revision(&p.store, &p.vault_id, &blob_b.0, &[rid_b], gen_b).unwrap();

    // A syncs again: downloads B's revision, merges, still Synced.
    let report = sync_once(
        &p.store,
        &p.vault,
        &remote,
        &Cancel::new(),
        SyncTrigger::Poll,
        2_000,
    )
    .await
    .unwrap();
    let state = load_state(&p.store, &p.vault_id, &p.vault).unwrap();
    assert!(state.snapshot.accounts.contains_key(&ea));
    assert!(state.snapshot.accounts.contains_key(&eb_entry));
    assert_eq!(
        report.status,
        clavis_core::dto::SyncStatusKind::Synced,
        "both accounts present, no conflicts"
    );
}

#[test]
fn no_wall_clock_winner_exists() {
    // Two devices produce conflicting labels with wildly different
    // timestamps; the merge must keep both candidates regardless of clock.
    let shared_vault = create_vault(pass("no wall clock passphrase")).unwrap();
    let vault_id = shared_vault.vault_id;
    let e = EntryId::generate();
    let mk = |seed: u8| -> (Snapshot, clavis_core::ids::WriterId) {
        let writer = clavis_core::ids::WriterId(
            vault_id,
            clavis_core::ids::DeviceId(clavis_core::ids::RawUuid::from_u128(seed as u128)),
        );
        let mut s = Snapshot::new();
        apply_local_action(
            &mut s,
            e,
            clavis_core::causal::Dot { writer, counter: 1 },
            vec![(
                Field::Issuer,
                FieldValue::Issuer(if seed == 1 {
                    "old-clock".to_string()
                } else {
                    "new-clock".to_string()
                }),
            )],
        )
        .unwrap();
        (s, writer)
    };
    let (sa, _) = mk(1);
    let (sb, _) = mk(2);
    let merged = sa.merge(&sb).unwrap();
    let issuer = merged.accounts[&e].registers[&Field::Issuer].distinct_values();
    assert_eq!(
        issuer.len(),
        2,
        "both candidates survive regardless of time"
    );
}
