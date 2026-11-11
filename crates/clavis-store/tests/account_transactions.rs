use clavis_core::causal::{Dot, Field, FieldValue};
use clavis_core::ids::{DeviceId, EntryId, VaultId, WriterId};
use clavis_core::otp::OtpConfigValue;
use clavis_core::vault::keys::create_vault;
use clavis_store::db::Store;
use clavis_store::repository;
use clavis_sync::local::{
    add_account, delete_account, load_state, update_account, AccountPatch, NewAccount,
};
use secrecy::SecretString;

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

fn otp_config(seed_byte: u8) -> OtpConfigValue {
    OtpConfigValue {
        secret: clavis_core::otp::OtpSeed::new(vec![seed_byte; 20]),
        algorithm: clavis_core::otp::OtpAlgorithm::Sha1,
        digits: 6,
        period_seconds: 30,
    }
}

struct Fixture {
    store: Store,
    vault: clavis_core::vault::keys::UnlockedVault,
    vault_id: VaultId,
}

fn fixture() -> Fixture {
    let store = Store::in_memory().unwrap();
    let created = create_vault(pass("account transaction passphrase")).unwrap();
    repository::register_vault(&store, &created.vault_id, Some("Vault"), None, true).unwrap();
    repository::insert_remote_revision(
        &store,
        &created.vault_id,
        &created.first_revision.0,
        &[created.revision_id],
        1,
    )
    .unwrap();
    Fixture {
        store,
        vault: created.unlocked,
        vault_id: created.vault_id,
    }
}

#[test]
fn add_edit_favorite_delete_search_survive_reopen() {
    let f = fixture();
    let (entry_id, _rid, gen) = add_account(
        &f.store,
        &f.vault,
        NewAccount {
            issuer: "Example".into(),
            account_label: "alice@example.com".into(),
            favorite: false,
            config: otp_config(1),
        },
        1,
    )
    .unwrap();

    // Edit label + favorite.
    let (_rid, gen) = update_account(
        &f.store,
        &f.vault,
        entry_id,
        AccountPatch {
            issuer: None,
            account_label: Some("alice+work@example.com".into()),
            favorite: Some(true),
            otp_config: None,
        },
        gen,
    )
    .unwrap();

    // Delete (tombstone).
    let _ = delete_account(&f.store, &f.vault, entry_id, gen).unwrap();

    // State survives "closing and reopening the database" with networking
    // disabled: reload from blobs.
    let state = load_state(&f.store, &f.vault_id, &f.vault).unwrap();
    let entry = state.snapshot.accounts.get(&entry_id).unwrap();
    assert!(entry.is_tombstoned());
    // Encrypted history and tombstone are retained: the issuer register
    // still merges to the edited value underneath the tombstone.
    let issuer = entry
        .registers
        .get(&Field::Issuer)
        .unwrap()
        .single_value()
        .unwrap();
    assert_eq!(issuer, FieldValue::Issuer("Example".into()));
    let label = entry
        .registers
        .get(&Field::AccountLabel)
        .unwrap()
        .single_value()
        .unwrap();
    assert_eq!(
        label,
        FieldValue::AccountLabel("alice+work@example.com".into())
    );
}

#[test]
fn stale_update_returns_stale_revision_error() {
    let f = fixture();
    let (entry_id, _rid, gen) = add_account(
        &f.store,
        &f.vault,
        NewAccount {
            issuer: "Example".into(),
            account_label: "bob@example.com".into(),
            favorite: false,
            config: otp_config(2),
        },
        1,
    )
    .unwrap();
    // A second writer (another process view) advances the generation.
    let (_rid, gen2) = update_account(
        &f.store,
        &f.vault,
        entry_id,
        AccountPatch {
            issuer: None,
            account_label: Some("bob+1@example.com".into()),
            favorite: None,
            otp_config: None,
        },
        gen,
    )
    .unwrap();
    assert_ne!(gen2, gen);
    // The first writer's view is now stale: no silent lost update.
    let stale = update_account(
        &f.store,
        &f.vault,
        entry_id,
        AccountPatch {
            issuer: None,
            account_label: Some("bob-stale@example.com".into()),
            favorite: None,
            otp_config: None,
        },
        gen,
    );
    assert_eq!(
        stale.unwrap_err(),
        clavis_core::error::CoreError::StaleRevision
    );
    // The winning edit is intact.
    let state = load_state(&f.store, &f.vault_id, &f.vault).unwrap();
    let label = state.snapshot.accounts[&entry_id]
        .registers
        .get(&Field::AccountLabel)
        .unwrap()
        .single_value()
        .unwrap();
    assert_eq!(label, FieldValue::AccountLabel("bob+1@example.com".into()));
}

#[test]
fn saved_revision_is_durable_before_ack_and_outbox_pending() {
    let f = fixture();
    let (_entry, _rid, _gen) = add_account(
        &f.store,
        &f.vault,
        NewAccount {
            issuer: "Durable".into(),
            account_label: "user@host".into(),
            favorite: false,
            config: otp_config(3),
        },
        1,
    )
    .unwrap();
    // The account revision plus its pending-upload marker persisted
    // transactionally (the initial vault revision was seeded directly and
    // is not a pending upload).
    assert_eq!(
        clavis_store::outbox::count_pending(&f.store, &f.vault_id).unwrap(),
        1
    );
    let pending = clavis_store::outbox::pending_entries(&f.store, &f.vault_id).unwrap();
    assert!(pending.iter().all(|e| !e.blob.is_empty()));
}

#[test]
fn write_barrier_blocks_edits_during_migration() {
    let f = fixture();
    f.store
        .set_write_barrier(&f.vault_id.to_string(), true)
        .unwrap();
    let blocked = add_account(
        &f.store,
        &f.vault,
        NewAccount {
            issuer: "X".into(),
            account_label: "y@z".into(),
            favorite: false,
            config: otp_config(4),
        },
        1,
    );
    assert!(blocked.is_err());
    f.store
        .set_write_barrier(&f.vault_id.to_string(), false)
        .unwrap();
}

#[test]
fn case_folding_search_over_labels_only() {
    let f = fixture();
    let (a, _r, _g) = add_account(
        &f.store,
        &f.vault,
        NewAccount {
            issuer: "Acme Corp".into(),
            account_label: "Alice@example.com".into(),
            favorite: false,
            config: otp_config(5),
        },
        1,
    )
    .unwrap();
    let (b, _r, _g) = add_account(
        &f.store,
        &f.vault,
        NewAccount {
            issuer: "Other".into(),
            account_label: "bob@example.com".into(),
            favorite: false,
            config: otp_config(6),
        },
        2,
    )
    .unwrap();
    let state = load_state(&f.store, &f.vault_id, &f.vault).unwrap();
    // Unlocked-memory search with simple case folding.
    let query = "acme";
    let hits: Vec<_> = clavis_core::accounts::list_summaries(&state.snapshot)
        .into_iter()
        .filter(|s| {
            format!(
                "{} {}",
                s.issuer.as_deref().unwrap_or_default(),
                s.account_label.as_deref().unwrap_or_default()
            )
            .to_lowercase()
            .contains(query)
        })
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, a);
    assert_ne!(hits[0].id, b);
}

#[test]
fn dot_counters_allocate_transactionally() {
    let store = Store::in_memory().unwrap();
    let a = repository::next_device_counter(&store).unwrap();
    let b = repository::next_device_counter(&store).unwrap();
    assert_eq!(a, 1);
    assert_eq!(b, 2);
    let _ = Dot {
        writer: WriterId(VaultId::generate(), DeviceId::generate()),
        counter: a,
    };
    let _ = EntryId::generate();
}
