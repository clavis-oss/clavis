//! Opens the committed cross-client fixture (tests/fixtures/vault-v1/).
//! The fixture proves that any client built against this format — current
//! or future — reads the same bytes identically. Synthetic data only.

use secrecy::SecretString;

use clavis_core::causal::{Field, FieldValue};
use clavis_core::vault::keys::{open_revision, UnlockCredential};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn opens_committed_v1_fixture() {
    let meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read("../../tests/fixtures/vault-v1/fixture.json").unwrap(),
    )
    .unwrap();
    let hex = std::fs::read_to_string("../../tests/fixtures/vault-v1/revision.hex").unwrap();
    let bytes = hex_decode(hex.trim());
    let passphrase = meta["passphrase"].as_str().unwrap();
    let (snapshot, _, revision_id) = open_revision(
        &bytes,
        &UnlockCredential::Passphrase(SecretString::new(passphrase.to_string().into())),
    )
    .expect("fixture must open with its documented passphrase");
    assert_eq!(revision_id.0.to_string(), meta["revision_id"]);
    assert_eq!(snapshot.accounts.len(), 1);
    let entry = snapshot.accounts.values().next().unwrap();
    assert_eq!(
        entry.registers[&Field::Issuer].single_value(),
        Some(FieldValue::Issuer("Fixture".into()))
    );
    // Wrong passphrase fails without altering anything (bytes compared).
    let before = bytes.clone();
    assert!(open_revision(
        &bytes,
        &UnlockCredential::Passphrase(SecretString::new("wrong-passphrase-xyz".into())),
    )
    .is_err());
    let hex2 = std::fs::read_to_string("../../tests/fixtures/vault-v1/revision.hex").unwrap();
    assert_eq!(hex_decode(hex2.trim()), before);
}
