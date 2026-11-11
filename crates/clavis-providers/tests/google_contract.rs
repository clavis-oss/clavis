#![allow(dead_code)] // some scripted helpers exist for parity with other adapters
mod scripted_http;

use std::sync::Arc;

use clavis_core::ids::{RevisionId, VaultId};
use clavis_providers::google::GoogleDriveStore;
use clavis_providers::oauth::google_config;
use clavis_sync::transport::{digest, RemoteStore};
use scripted_http::ScriptedHttp;
use secrecy::SecretString;

fn store(http: Arc<ScriptedHttp>) -> GoogleDriveStore {
    let s = GoogleDriveStore::new(http, google_config("test-client", 0));
    s.set_access_token(SecretString::new("test-token".into()));
    s
}

#[tokio::test]
async fn list_walks_pages_and_parses_drive_shapes() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(
        200,
        r#"{"nextPageToken":"tok2","files":[{"id":"f1","name":"clavis-11111111-1111-1111-1111-111111111111-22222222-2222-2222-2222-222222222222.clv","size":"123","md5Checksum":"abc"},{"id":"bogus","name":"unrelated.txt","size":"1"}]}"#,
    );
    http.push_json(
        200,
        r#"{"files":[{"id":"f2","name":"clavis-11111111-1111-1111-1111-111111111111-33333333-3333-3333-3333-333333333333.clv","size":"456"}]}"#,
    );
    let s = store(http.clone());
    let vault = VaultId("11111111-1111-1111-1111-111111111111".parse().unwrap());
    let page1 = s.list_page(&vault, None).await.unwrap();
    assert_eq!(page1.objects.len(), 1, "unrelated names are ignored");
    assert_eq!(page1.objects[0].locator, "f1");
    assert_eq!(page1.objects[0].size, 123, "Drive reports size as a string");
    let page2 = s
        .list_page(&vault, page1.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(page2.objects.len(), 1);
    // The query is scoped to the vault's object names.
    let req = http.last_request();
    assert!(req.url.contains("clavis-11111111-"));
    assert!(req.url.contains("trashed+%3D+false") || req.url.contains("trashed"));
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == "Bearer test-token"));
}

#[tokio::test]
async fn upload_is_multipart_and_download_returns_bytes() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(200, r#"{"id":"new-file-1","name":"x.clv"}"#);
    let s = store(http.clone());
    let vault = VaultId("11111111-1111-1111-1111-111111111111".parse().unwrap());
    let rid = RevisionId::generate();
    let bytes = vec![7u8; 128];
    let receipt = s.create_object(&vault, &rid, bytes.clone()).await.unwrap();
    assert_eq!(receipt.locator, "new-file-1");
    assert_eq!(receipt.digest, digest(&bytes));
    // Download returns exactly the stored bytes.
    http.push_bytes(200, &bytes);
    let downloaded = s.get_object("new-file-1").await.unwrap();
    assert_eq!(downloaded, bytes);
}

#[tokio::test]
async fn status_mapping_is_typed() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(401, r#"{"error":"invalid_credentials"}"#);
    let s = store(http);
    let vault = VaultId("11111111-1111-1111-1111-111111111111".parse().unwrap());
    let err = s.list_page(&vault, None).await.unwrap_err();
    assert_eq!(err.kind(), "unauthorized");

    let http = Arc::new(ScriptedHttp::new());
    http.push(Ok(http_response_429()));
    let s = store(http);
    let err = s.list_page(&vault, None).await.unwrap_err();
    assert_eq!(err.kind(), "rate_limited");
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(42)));

    let http = Arc::new(ScriptedHttp::new());
    http.push_json(507, r#"{}"#);
    let s = store(http);
    let err = s.list_page(&vault, None).await.unwrap_err();
    assert_eq!(err.kind(), "quota_exceeded");
}

fn http_response_429() -> clavis_providers::oauth::HttpResponse {
    clavis_providers::oauth::HttpResponse {
        status: 429,
        body: Vec::new(),
        retry_after_secs: Some(42),
    }
}

impl ScriptedHttp {
    fn push_bytes(&self, status: u16, body: &[u8]) {
        self.responses
            .lock()
            .unwrap()
            .push(Ok(clavis_providers::oauth::HttpResponse {
                status,
                body: body.to_vec(),
                retry_after_secs: None,
            }));
    }

    fn push_raw_bytes(&self) {
        self.push_bytes(200, b"placeholder");
    }
}
