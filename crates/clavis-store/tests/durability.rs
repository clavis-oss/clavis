use clavis_core::vault::keys::{create_vault, UnlockCredential};
use clavis_store::db::Store;
use secrecy::SecretString;

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

/// A distinct synthetic sentinel proves plaintext secrets never reach the
/// database file (nor a WAL/journal companion).
const SENTINEL: &str = "SENTINEL-super-secret-seed-or-refresh-token-73731";

#[test]
fn interrupted_transaction_leaves_previous_committed_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clavis.sqlite");
    let store = Store::open(&path).unwrap();
    store.config_set("before", "committed-value").unwrap();

    // Rollback path: a transaction that errors must leave the previous
    // committed state intact.
    let result: Result<(), clavis_core::error::CoreError> = store.tx(|_conn| {
        _conn
            .execute(
                "UPDATE config SET value = 'clobbered' WHERE key = 'before'",
                [],
            )
            .map_err(|_| clavis_core::error::CoreError::StorageFailure)?;
        Err(clavis_core::error::CoreError::StorageFailure)
    });
    assert!(result.is_err());
    // The previous committed state is intact.
    assert_eq!(
        store.config_get("before").unwrap().as_deref(),
        Some("committed-value")
    );
}

#[test]
fn database_bytes_never_contain_secret_sentinel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clavis.sqlite");
    let store = Store::open(&path).unwrap();

    let created = create_vault(pass("durable vault passphrase")).unwrap();
    clavis_store::repository::register_vault(&store, &created.vault_id, Some("Vault"), None, true)
        .unwrap();
    clavis_store::repository::insert_remote_revision(
        &store,
        &created.vault_id,
        &created.first_revision.0,
        &[created.revision_id],
        1,
    )
    .unwrap();

    // Encrypt credentials containing the sentinel with the device store.
    let device_key = clavis_store::credentials::load_or_create_device_key(&path).unwrap();
    let cred_store = clavis_store::credentials::CredentialStore::new(created.vault_id, device_key);
    cred_store
        .put(&store, "provider:google_drive", SENTINEL.as_bytes())
        .unwrap();

    // Re-open to flush any journal state, then scan raw bytes.
    drop(store);
    let mut blob = std::fs::read(&path).unwrap();
    if let Ok(journal) = std::fs::read(dir.path().join("clavis.sqlite-journal")) {
        blob.extend_from_slice(&journal);
    }
    assert!(
        !window_contains(&blob, SENTINEL.as_bytes()),
        "plaintext sentinel found in on-disk database bytes"
    );
    // The encrypted round trip still recovers it (fresh DeviceKey instance).
    let store = Store::open(&path).unwrap();
    let device_key2 = clavis_store::credentials::load_or_create_device_key(&path).unwrap();
    let cred_store = clavis_store::credentials::CredentialStore::new(created.vault_id, device_key2);
    let recovered = cred_store
        .get(&store, "provider:google_drive")
        .unwrap()
        .unwrap();
    assert_eq!(recovered, SENTINEL.as_bytes());
}

#[test]
fn wrong_vault_id_cannot_decrypt_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clavis.sqlite");
    let store = Store::open(&path).unwrap();
    let device_key = clavis_store::credentials::load_or_create_device_key(&path).unwrap();
    let vault_a = clavis_core::ids::VaultId::generate();
    let cred_a = clavis_store::credentials::CredentialStore::new(vault_a, device_key);
    cred_a.put(&store, "k", SENTINEL.as_bytes()).unwrap();
    // A different vault namespace cannot read the blob (fresh DeviceKey).
    let vault_b = clavis_core::ids::VaultId::generate();
    let device_key2 = clavis_store::credentials::load_or_create_device_key(&path).unwrap();
    let cred_b = clavis_store::credentials::CredentialStore::new(vault_b, device_key2);
    assert!(cred_b.get(&store, "k").is_err());
}

#[test]
fn store_file_has_user_only_permissions() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clavis.sqlite");
        let _store = Store::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn stale_generation_is_rejected_on_commit() {
    let store = Store::in_memory().unwrap();
    let created = create_vault(pass("stale edit passphrase")).unwrap();
    clavis_store::repository::register_vault(&store, &created.vault_id, Some("Vault"), None, true)
        .unwrap();
    clavis_store::repository::insert_remote_revision(
        &store,
        &created.vault_id,
        &created.first_revision.0,
        &[created.revision_id],
        1,
    )
    .unwrap();
    // Commit at generation 1, then attempt a second commit still claiming
    // generation 1 (stale view): must be rejected.
    let (_, gen) = clavis_store::repository::read_heads(&store, &created.vault_id).unwrap();
    assert_eq!(gen, 1);
    let blob2 = clavis_core::vault::keys::seal_revision(
        &created.unlocked,
        &clavis_core::causal::Snapshot::new(),
        &[created.revision_id],
    )
    .unwrap();
    let rid2 = clavis_store::repository::commit_local_revision(
        &store,
        &created.vault_id,
        &blob2.0,
        &[created.revision_id],
        1,
    )
    .unwrap();
    let blob3 = clavis_core::vault::keys::seal_revision(
        &created.unlocked,
        &clavis_core::causal::Snapshot::new(),
        &[rid2],
    )
    .unwrap();
    let stale = clavis_store::repository::commit_local_revision(
        &store,
        &created.vault_id,
        &blob3.0,
        &[rid2],
        1, // stale: current generation is now 2
    );
    assert_eq!(
        stale.unwrap_err(),
        clavis_core::error::CoreError::StaleRevision
    );
}

fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// Silence unused-import lint when cfg(unix) hides usage.
#[allow(unused)]
fn _unused(_: UnlockCredential) {}
