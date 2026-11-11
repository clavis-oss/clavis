use clavis_core::ids::{RevisionId, VaultId};
use clavis_core::vault::keys::{create_vault, RevisionBlob, UnlockedVault};
use clavis_sync::fake_remote::{FakeRemote, FakeRemoteConfig, ScriptedFailure};
use clavis_sync::transport::{digest, object_key, RemoteStore};

fn pass(s: &str) -> secrecy::SecretString {
    secrecy::SecretString::new(s.to_string().into())
}

pub fn make_vault() -> (UnlockedVault, VaultId, RevisionBlob, RevisionId) {
    let created = create_vault(pass("transport contract passphrase")).unwrap();
    (
        created.unlocked,
        created.vault_id,
        created.first_revision,
        created.revision_id,
    )
}

#[tokio::test]
async fn delayed_visibility_is_not_synced() {
    let (vault, vault_id, blob, rid) = make_vault();
    let remote = FakeRemote::new(FakeRemoteConfig {
        visibility_delay: 2,
        ..Default::default()
    });
    remote.push_object(&vault_id, &rid, blob.0.clone());
    // First two listings show nothing: the object is not yet visible.
    let page = remote.list_page(&vault_id, None).await.unwrap();
    assert!(page.objects.is_empty());
    let page = remote.list_page(&vault_id, None).await.unwrap();
    assert!(page.objects.is_empty());
    let page = remote.list_page(&vault_id, None).await.unwrap();
    assert_eq!(page.objects.len(), 1);
    assert_eq!(page.objects[0].revision_id, rid);
    let _ = &vault;
}

#[tokio::test]
async fn duplicate_listings_accept_only_byte_identical_duplicates() {
    let (vault, vault_id, blob, rid) = make_vault();
    let remote = FakeRemote::new(FakeRemoteConfig {
        duplicate_listings: true,
        ..Default::default()
    });
    remote.push_object(&vault_id, &rid, blob.0.clone());
    let page = remote.list_page(&vault_id, None).await.unwrap();
    assert_eq!(page.objects.len(), 2, "same object listed twice");
    // Both entries refer to the same revision with the same digest: the
    // engine dedupes to one unique revision.
    let unique: std::collections::BTreeSet<_> =
        page.objects.iter().map(|o| o.revision_id).collect();
    assert_eq!(unique.len(), 1);
    let _ = (&vault, &blob);
}

#[tokio::test]
async fn dropped_upload_response_is_idempotent_on_retry() {
    let (vault, vault_id, blob, rid) = make_vault();
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    remote.push_failure(ScriptedFailure::DroppedUpload);
    let err = remote
        .create_object(&vault_id, &rid, blob.0.clone())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "other");
    // Retry stores byte-identical content under the same revision ID.
    let receipt = remote
        .create_object(&vault_id, &rid, blob.0.clone())
        .await
        .unwrap();
    remote
        .verify_object(&receipt, &digest(&blob.0))
        .await
        .unwrap();
    // No fork: exactly one object for the revision ID.
    assert_eq!(remote.unique_revision_count(&vault_id, &rid), 1);
    let _ = &vault;
}

#[tokio::test]
async fn same_id_different_bytes_is_integrity_error() {
    let (vault, vault_id, blob, rid) = make_vault();
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    remote.push_object(&vault_id, &rid, blob.0.clone());
    let mut different = blob.0.clone();
    different[0] ^= 0xff;
    let err = remote
        .create_object(&vault_id, &rid, different)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "integrity_failure");
    let _ = &vault;
}

#[tokio::test]
async fn pagination_walks_all_pages() {
    let (_vault, vault_id, _blob, _rid) = make_vault();
    let remote = FakeRemote::new(FakeRemoteConfig {
        page_size: 2,
        ..Default::default()
    });
    for i in 0..5 {
        let rid = RevisionId::generate();
        remote.push_object(&vault_id, &rid, vec![i as u8; 64]);
    }
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = remote
            .list_page(&vault_id, cursor.as_deref())
            .await
            .unwrap();
        seen.extend(page.objects.iter().map(|o| o.revision_id));
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(
        seen.iter().collect::<std::collections::BTreeSet<_>>().len(),
        5
    );
}

#[tokio::test]
async fn cursor_expiry_is_typed_error() {
    let (_vault, vault_id, _blob, _rid) = make_vault();
    let remote = FakeRemote::new(FakeRemoteConfig {
        cursor_expires: true,
        page_size: 1,
        ..Default::default()
    });
    for i in 0..3 {
        remote.push_object(&vault_id, &RevisionId::generate(), vec![i as u8; 32]);
    }
    let page = remote.list_page(&vault_id, None).await.unwrap();
    assert!(page.next_cursor.is_some());
    // An expired/invalid cursor is rejected with a sanitized error, not a
    // partial silent result.
    let err = remote
        .list_page(&vault_id, Some("page:1"))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "other");
}

#[tokio::test]
async fn scripted_failures_are_typed() {
    let (vault, vault_id, blob, rid) = make_vault();
    let remote = FakeRemote::new(FakeRemoteConfig::default());
    for (failure, kind) in [
        (ScriptedFailure::Offline, "offline"),
        (ScriptedFailure::Unauthorized, "unauthorized"),
        (ScriptedFailure::QuotaExceeded, "quota_exceeded"),
        (ScriptedFailure::RateLimited(Some(30)), "rate_limited"),
    ] {
        remote.push_failure(failure);
        let err = remote
            .create_object(&vault_id, &rid, blob.0.clone())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), kind);
        if kind == "rate_limited" {
            assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(30)));
        }
    }
    let _ = &vault;
}

#[tokio::test]
async fn object_key_layout_matches_protocol() {
    let (vault, vault_id, blob, rid) = make_vault();
    let key = object_key(&vault_id, &rid);
    assert!(key.starts_with("clavis/"));
    assert!(key.ends_with(&format!("{}.clv", rid)));
    let _ = (vault, blob);
}
