// One-off generator for tests/fixtures/vault-v1/*.clv.revision.hex
// (synthetic data only; the passphrase is public on purpose).
use secrecy::SecretString;
fn main() {
    let created =
        clavis_core::vault::keys::create_vault(SecretString::new("fixture-passphrase-123".into()))
            .unwrap();
    let mut snapshot = clavis_core::causal::Snapshot::new();
    let writer = clavis_core::ids::WriterId(
        created.vault_id,
        clavis_core::ids::DeviceId(clavis_core::ids::RawUuid::from_u128(0xfee1dead)),
    );
    let entry = clavis_core::ids::EntryId::generate();
    clavis_core::vault::keys::apply_local_action(
        &mut snapshot,
        entry,
        clavis_core::causal::Dot { writer, counter: 1 },
        vec![
            (
                clavis_core::causal::Field::Issuer,
                clavis_core::causal::FieldValue::Issuer("Fixture".into()),
            ),
            (
                clavis_core::causal::Field::AccountLabel,
                clavis_core::causal::FieldValue::AccountLabel("fixture@example.com".into()),
            ),
            (
                clavis_core::causal::Field::OtpConfig,
                clavis_core::causal::FieldValue::OtpConfig(clavis_core::otp::OtpConfigValue {
                    secret: clavis_core::otp::OtpSeed::new(vec![0xAB; 20]),
                    algorithm: clavis_core::otp::OtpAlgorithm::Sha1,
                    digits: 6,
                    period_seconds: 30,
                }),
            ),
        ],
    )
    .unwrap();
    let blob = clavis_core::vault::keys::seal_revision(
        &created.unlocked,
        &snapshot,
        &[created.revision_id],
    )
    .unwrap();
    let sealed_id = clavis_core::vault::keys::revision_id_of(&blob).unwrap();
    std::fs::write("tests/fixtures/vault-v1/revision.hex", hex(&blob.0)).unwrap();
    let meta = serde_json::json!({
        "format": 1,
        "passphrase": "fixture-passphrase-123",
        "vault_id": created.vault_id.to_string(),
        "revision_id": sealed_id.to_string(),
        "parent_id": created.revision_id.to_string(),
        "entry_id": entry.to_string(),
        "expected": {
            "issuer": "Fixture",
            "account_label": "fixture@example.com",
            "otp": { "algorithm": "SHA1", "digits": 6, "period_seconds": 30 }
        }
    });
    std::fs::write(
        "tests/fixtures/vault-v1/fixture.json",
        serde_json::to_vec_pretty(&meta).unwrap(),
    )
    .unwrap();
    println!("fixture vault_id={}", created.vault_id);
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
