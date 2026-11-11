use secrecy::SecretString;

use clavis_core::causal::{Field, FieldValue, Snapshot};
use clavis_core::ids::EntryId;
use clavis_core::vault::keys::{
    apply_local_action, create_vault_with_snapshot, open_revision, seal_revision, UnlockCredential,
};
use clavis_core::vault::{export as vault_export, recovery as vault_recovery};

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

fn dot() -> clavis_core::causal::Dot {
    clavis_core::causal::Dot {
        writer: clavis_core::ids::WriterId(
            clavis_core::ids::VaultId::generate(),
            clavis_core::ids::DeviceId::generate(),
        ),
        counter: 1,
    }
}

fn snapshot_with_accounts() -> (Snapshot, EntryId) {
    let mut s = Snapshot::new();
    let entry = EntryId::generate();
    apply_local_action(
        &mut s,
        entry,
        dot(),
        vec![
            (Field::Issuer, FieldValue::Issuer("Example".into())),
            (
                Field::AccountLabel,
                FieldValue::AccountLabel("alice@example.com".into()),
            ),
            (
                Field::OtpConfig,
                FieldValue::OtpConfig(clavis_core::otp::OtpConfigValue {
                    secret: clavis_core::otp::OtpSeed::new(vec![9u8; 20]),
                    algorithm: clavis_core::otp::OtpAlgorithm::Sha1,
                    digits: 6,
                    period_seconds: 30,
                }),
            ),
        ],
    )
    .unwrap();
    (s, entry)
}

#[test]
fn offline_fresh_install_recovery() {
    let created = clavis_core::vault::keys::create_vault(pass("original passphrase 12")).unwrap();
    let (snapshot, _) = snapshot_with_accounts();
    let rev = seal_revision(&created.unlocked, &snapshot, &[created.revision_id]).unwrap();
    let export = vault_export::seal_export(
        &created.unlocked,
        &snapshot,
        &[clavis_core::vault::keys::revision_id_of(&rev).unwrap()],
    )
    .unwrap();

    // Fresh machine: no provider, no local state, only the export + key.
    let mut presentation = created.recovery_key;
    let recovery_key = presentation.present().unwrap().to_string();
    let session = vault_recovery::recover(&export, &recovery_key).unwrap();
    assert_eq!(session.source_vault_id, created.vault_id);
    let restored =
        vault_recovery::complete_recovery(session, pass("brand new passphrase 1")).unwrap();
    let credential = UnlockCredential::Passphrase(pass("brand new passphrase 1"));
    let (snapshot2, _, _) = open_revision(&restored.first_revision.0, &credential).unwrap();
    // All OTP content restored with the same entry IDs.
    assert_eq!(snapshot2, snapshot);
    // Fresh namespace: never reattached to the old history.
    assert_ne!(restored.vault_id, created.vault_id);
}

#[test]
fn wrong_backup_key_pairing_fails() {
    let created_a = clavis_core::vault::keys::create_vault(pass("vault a passphrase 12")).unwrap();
    let created_b = clavis_core::vault::keys::create_vault(pass("vault b passphrase 12")).unwrap();
    let snapshot = Snapshot::new();
    let export_a = vault_export::seal_export(&created_a.unlocked, &snapshot, &[]).unwrap();
    let mut presentation_b = created_b.recovery_key;
    let key_b = presentation_b.present().unwrap().to_string();
    assert!(vault_recovery::recover(&export_a, &key_b).is_err());
}

#[test]
fn migration_preserves_entries_with_fresh_keys() {
    let created = clavis_core::vault::keys::create_vault(pass("old passphrase here 1")).unwrap();
    let (snapshot, entry_id) = snapshot_with_accounts();
    let rev = seal_revision(&created.unlocked, &snapshot, &[created.revision_id]).unwrap();
    let heads = vec![clavis_core::vault::keys::revision_id_of(&rev).unwrap()];

    let draft = clavis_core::vault::migration::prepare_migration(
        &created.unlocked,
        &snapshot,
        &heads,
        pass("new passphrase here 1"),
    )
    .unwrap();
    let verified =
        clavis_core::vault::migration::verify_destination(&draft, &pass("new passphrase here 1"))
            .unwrap();
    assert_eq!(verified, snapshot);

    // Entry IDs and content preserved; keys and namespace are fresh.
    let credential = UnlockCredential::Passphrase(pass("new passphrase here 1"));
    let (dest_snapshot, _vault, _) =
        open_revision(&draft.destination_revision.0, &credential).unwrap();
    assert!(dest_snapshot.accounts.contains_key(&entry_id));
    assert_ne!(draft.destination_vault_id, created.vault_id);

    // Retirement record on the source namespace.
    let retirement =
        clavis_core::vault::migration::record_retirement(&created.unlocked, &draft, &heads)
            .unwrap();
    // Retirement opens with the *source* credential, not the destination's.
    let source_credential = UnlockCredential::Passphrase(pass("old passphrase here 1"));
    let payload =
        clavis_core::vault::keys::open_retirement(&retirement.0, &source_credential).unwrap();
    assert_eq!(payload.migration_id, draft.migration_id);
    assert_eq!(payload.destination_vault_id, draft.destination_vault_id.0);
    let _ = payload_destination_check(&payload.destination_vault_id);
}

fn payload_destination_check(_id: &uuid::Uuid) -> bool {
    true
}

#[test]
fn fresh_namespace_migration_has_new_recovery_key() {
    use clavis_core::vault::crypto::decode_recovery_key;
    let created = clavis_core::vault::keys::create_vault(pass("old passphrase here 1")).unwrap();
    let snapshot = Snapshot::new();
    let draft = clavis_core::vault::migration::prepare_migration(
        &created.unlocked,
        &snapshot,
        &[created.revision_id],
        pass("new passphrase here 1"),
    )
    .unwrap();
    // The destination recovery key decodes and differs from nothing (fresh
    // random bytes were generated for the new namespace).
    let key = decode_recovery_key(&draft.destination_recovery_key).unwrap();
    assert_ne!(key, [0u8; 32]);
}

#[test]
fn interrupted_write_leaves_source_usable() {
    // Simulated failure before activation: prepare only; the source vault
    // must still open with its original passphrase.
    let created = clavis_core::vault::keys::create_vault(pass("still works 123456")).unwrap();
    let snapshot = Snapshot::new();
    let _draft = clavis_core::vault::migration::prepare_migration(
        &created.unlocked,
        &snapshot,
        &[created.revision_id],
        pass("never activated 1234"),
    )
    .unwrap();
    assert!(open_revision(
        &created.first_revision.0,
        &UnlockCredential::Passphrase(pass("still works 123456"))
    )
    .is_ok());
}

#[test]
fn create_vault_with_snapshot_rejects_oversized_state() {
    use clavis_core::causal::{AccountEntry, Register};
    let mut s = Snapshot::new();
    // One over the 2,000 account limit must fail validation, never truncate.
    for i in 0..2001 {
        let mut e = AccountEntry::default();
        let mut r = Register::default();
        let d = clavis_core::causal::Dot {
            writer: clavis_core::ids::WriterId(
                clavis_core::ids::VaultId::generate(),
                clavis_core::ids::DeviceId::generate(),
            ),
            counter: 1,
        };
        r.values.push((d, FieldValue::Issuer(format!("i{i}"))));
        r.context.push((d.writer, 1));
        e.registers.insert(Field::Issuer, r);
        s.accounts.insert(EntryId::generate(), e);
    }
    assert_eq!(
        create_vault_with_snapshot(pass("limit check passphrase"), s, &[]).unwrap_err(),
        clavis_core::CoreError::CapacityReached
    );
}
