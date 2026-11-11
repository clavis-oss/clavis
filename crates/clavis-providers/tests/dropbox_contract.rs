mod scripted_http;

use std::sync::Arc;

use clavis_core::ids::{RevisionId, VaultId};
use clavis_providers::dropbox::DropboxStore;
use clavis_providers::oauth::{dropbox_config, HttpRequest};
use clavis_sync::transport::{digest, RemoteStore};
use scripted_http::ScriptedHttp;
use secrecy::SecretString;

fn store(http: Arc<ScriptedHttp>) -> DropboxStore {
    let s = DropboxStore::new(http, dropbox_config("test-client", 0));
    s.set_access_token(SecretString::new("test-token".into()));
    s
}

#[tokio::test]
async fn list_folder_and_continue_cursors() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(
        200,
        r#"{"entries":[{".tag":"file","id":"id:a1","name":"aaaaaaa1-1111-1111-1111-111111111111.clv","size":50}],"cursor":"cur-1","has_more":true}"#,
    );
    http.push_json(
        200,
        r#"{"entries":[{".tag":"file","id":"id:a2","name":"aaaaaaa1-1111-1111-1111-111111111112.clv","size":60}],"cursor":"cur-2","has_more":false}"#,
    );
    let s = store(http.clone());
    let vault = VaultId("aaaaaaaa-1111-1111-1111-111111111111".parse().unwrap());
    let page1 = s.list_page(&vault, None).await.unwrap();
    assert_eq!(page1.objects.len(), 1);
    let page2 = s
        .list_page(&vault, page1.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(page2.objects.len(), 1);
    // Continuation used the documented endpoint with the cursor.
    let req: HttpRequest = http.last_request();
    assert!(req.url.contains("list_folder/continue"));
    assert!(String::from_utf8_lossy(&req.body).contains("cur-1"));
}

#[tokio::test]
async fn upload_uses_add_mode_never_overwrite() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(200, r#"{"id":"id:new","name":"x.clv","rev":"r1"}"#);
    let s = store(http.clone());
    let vault = VaultId("aaaaaaaa-1111-1111-1111-111111111111".parse().unwrap());
    let rid = RevisionId::generate();
    let bytes = vec![5u8; 64];
    let receipt = s.create_object(&vault, &rid, bytes.clone()).await.unwrap();
    assert_eq!(receipt.digest, digest(&bytes));
    let req: HttpRequest = http.last_request();
    assert!(req.headers.iter().any(|(k, v)| k == "dropbox-api-arg"
        && v.contains("\"mode\":\"add\"")
        && v.contains("\"autorename\":false")));
    // API revision IDs come back as transport metadata only.
    assert_eq!(receipt.locator, "id:new");
}

#[tokio::test]
async fn rate_limit_carries_retry_after() {
    let http = Arc::new(ScriptedHttp::new());
    http.push(Ok(clavis_providers::oauth::HttpResponse {
        status: 429,
        body: Vec::new(),
        retry_after_secs: Some(7),
    }));
    let s = store(http);
    let vault = VaultId("aaaaaaaa-1111-1111-1111-111111111111".parse().unwrap());
    let err = s.list_page(&vault, None).await.unwrap_err();
    assert_eq!(err.kind(), "rate_limited");
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(7)));
}

#[tokio::test]
async fn download_returns_exact_bytes() {
    let http = Arc::new(ScriptedHttp::new());
    let payload = vec![9u8; 77];
    http.push(Ok(clavis_providers::oauth::HttpResponse {
        status: 200,
        body: payload.clone(),
        retry_after_secs: None,
    }));
    let s = store(http.clone());
    let got = s.get_object("id:a1").await.unwrap();
    assert_eq!(got, payload);
    let req: HttpRequest = http.last_request();
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k == "dropbox-api-arg" && v.contains("id:a1")));
}
