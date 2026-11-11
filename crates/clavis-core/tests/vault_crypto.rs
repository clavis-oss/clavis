use secrecy::SecretString;

use clavis_core::causal::{Field, FieldValue, Snapshot};
use clavis_core::ids::EntryId;
use clavis_core::vault::keys::{
    apply_local_action, create_vault, open_container, open_retirement, open_revision,
    revision_id_of, seal_retirement, seal_revision, RetirementPayload, RevisionBlob,
    UnlockCredential,
};

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

fn snapshot_with_one_account() -> Snapshot {
    let mut s = Snapshot::new();
    let entry = EntryId::generate();
    apply_local_action(
        &mut s,
        entry,
        clavis_core::causal::Dot {
            writer: clavis_core::ids::WriterId(
                clavis_core::ids::VaultId::generate(),
                clavis_core::ids::DeviceId::generate(),
            ),
            counter: 1,
        },
        vec![
            (Field::Issuer, FieldValue::Issuer("Example".into())),
            (
                Field::OtpConfig,
                FieldValue::OtpConfig(clavis_core::otp::OtpConfigValue {
                    secret: clavis_core::otp::OtpSeed::new(vec![1u8; 20]),
                    algorithm: clavis_core::otp::OtpAlgorithm::Sha1,
                    digits: 6,
                    period_seconds: 30,
                }),
            ),
        ],
    )
    .unwrap();
    s
}

#[test]
fn roundtrip_passphrase() {
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    let (opened_snapshot, _vault, rev) = open_revision(
        &created.first_revision.0,
        &UnlockCredential::Passphrase(pass("correct horse battery staple")),
    )
    .unwrap();
    let original = Snapshot::new();
    assert_eq!(opened_snapshot, original);
    assert_eq!(rev, created.revision_id);
}

#[test]
fn roundtrip_recovery() {
    let mut created = create_vault(pass("correct horse battery staple")).unwrap();
    let recovery_key = created.recovery_key.present().unwrap().to_string();
    let (snapshot, _, _) = open_revision(
        &created.first_revision.0,
        &UnlockCredential::RecoveryKey(recovery_key),
    )
    .unwrap();
    assert_eq!(snapshot, Snapshot::new());
    let _ = &mut created;
}

#[test]
fn wrong_key_preserves_bytes() {
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    let source_before = created.first_revision.0.clone();
    let wrong = open_revision(
        &source_before,
        &UnlockCredential::Passphrase(pass("wrong passphrase 123")),
    );
    assert!(wrong.is_err());
    let source_after = created.first_revision.0.clone();
    assert_eq!(source_after, source_before);
}

#[test]
fn tampered_header_rejected() {
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    let mut bytes = created.first_revision.0.clone();
    // Flip a byte inside the header JSON region.
    let idx = 4 + 2 + 4 + 20;
    bytes[idx] ^= 0x01;
    let tampered = open_revision(
        &bytes,
        &UnlockCredential::Passphrase(pass("correct horse battery staple")),
    );
    assert!(tampered.is_err());
    // Tampered ciphertext too.
    let mut bytes2 = created.first_revision.0.clone();
    let last = bytes2.len() - 1;
    bytes2[last] ^= 0xff;
    assert!(open_revision(
        &bytes2,
        &UnlockCredential::Passphrase(pass("correct horse battery staple"))
    )
    .is_err());
}

#[test]
fn oversized_kdf_rejected_before_work() {
    use clavis_core::vault::format::parse_container;
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    // Craft a header claiming 512 MiB memory: must be rejected without KDF.
    let parsed = parse_container(&created.first_revision.0).unwrap();
    let mut header = parsed.header.clone();
    header.kdf.memory_kib = 512 * 1024;
    let sealed = clavis_core::vault::format::seal_container(
        clavis_core::vault::format::REVISION_MAGIC,
        &header,
        &parsed.ciphertext,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let result = open_revision(
        &sealed,
        &UnlockCredential::Passphrase(pass("correct horse battery staple")),
    );
    assert!(result.is_err());
    // Resource-limit rejection happens before any Argon2 work (which would
    // take far longer than 5 seconds at 512 MiB).
    assert!(start.elapsed().as_secs() < 5);
}

#[test]
fn nonces_are_distinct() {
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    let snapshot = snapshot_with_one_account();
    let a = seal_revision(&created.unlocked, &snapshot, &[created.revision_id]).unwrap();
    let b = seal_revision(&created.unlocked, &snapshot, &[created.revision_id]).unwrap();
    assert_ne!(a, b, "fresh payload nonce per revision");
    assert_ne!(revision_id_of(&a).unwrap(), revision_id_of(&b).unwrap());
}

#[test]
fn unicode_and_whitespace_passphrases_are_exact_bytes() {
    let p = "  pass phrase with  spaces and ünïcödé 🔐  ";
    let created = create_vault(pass(p)).unwrap();
    assert!(open_revision(
        &created.first_revision.0,
        &UnlockCredential::Passphrase(pass(p))
    )
    .is_ok());
    // No silent trimming: a trimmed passphrase must fail.
    assert!(open_revision(
        &created.first_revision.0,
        &UnlockCredential::Passphrase(pass(p.trim()))
    )
    .is_err());
}

#[test]
fn export_roundtrip_preserves_conflicts_and_is_container() {
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    let snapshot = snapshot_with_one_account();
    let rev = seal_revision(&created.unlocked, &snapshot, &[created.revision_id]).unwrap();
    let export = clavis_core::vault::export::seal_export(
        &created.unlocked,
        &snapshot,
        &[revision_id_of(&rev).unwrap()],
    )
    .unwrap();
    assert!(clavis_core::vault::export::is_export_container(&export));
    let contents = clavis_core::vault::export::open_export(
        &export,
        &UnlockCredential::Passphrase(pass("correct horse battery staple")),
    )
    .unwrap();
    assert_eq!(contents.snapshot, snapshot);
    assert_ne!(
        contents.source_vault_id,
        clavis_core::ids::VaultId::generate()
    );
    assert_eq!(contents.source_vault_id, created.vault_id);
    // A revision container must never open as an export (container-kind domain).
    let as_export = clavis_core::vault::export::open_export(
        &created.first_revision.0,
        &UnlockCredential::Passphrase(pass("correct horse battery staple")),
    );
    assert!(as_export.is_err());
}

#[test]
fn retirement_revision_roundtrip() {
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    let payload = RetirementPayload {
        migration_id: uuid::Uuid::new_v4(),
        destination_vault_id: clavis_core::ids::VaultId::generate().0,
        included_source_heads: vec![created.revision_id.0],
    };
    let blob: RevisionBlob =
        seal_retirement(&created.unlocked, &[created.revision_id], &payload).unwrap();
    let opened = open_retirement(
        &blob.0,
        &UnlockCredential::Passphrase(pass("correct horse battery staple")),
    )
    .unwrap();
    assert_eq!(opened, payload);
}

#[test]
fn oversized_passphrase_input_rejected() {
    let long = "x".repeat(1025);
    assert_eq!(
        create_vault(pass(&long)).unwrap_err(),
        clavis_core::CoreError::ResourceLimit
    );
}

#[test]
fn recovery_key_encoding_roundtrip() {
    use clavis_core::vault::crypto::{decode_recovery_key, encode_recovery_key};
    let bytes = [7u8; 32];
    let encoded = encode_recovery_key(&bytes);
    assert!(encoded.starts_with("clavis-recovery-v1:"));
    assert!(!encoded.contains('='), "unpadded base64url");
    assert_eq!(decode_recovery_key(&encoded).unwrap(), bytes);
}

#[test]
fn open_container_returns_root_key_for_session_reuse() {
    let created = create_vault(pass("correct horse battery staple")).unwrap();
    let (_, _, root) = open_container(
        &created.first_revision.0,
        &UnlockCredential::Passphrase(pass("correct horse battery staple")),
    )
    .unwrap();
    assert_ne!(root.bytes(), &[0u8; 32]);
}
