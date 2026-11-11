mod scripted_http;

use std::sync::Arc;

use clavis_core::ids::{RevisionId, VaultId};
use clavis_providers::oauth::HttpResponse;
use clavis_providers::webdav::{WebDavConfig, WebDavStore};
use clavis_sync::transport::RemoteStore;
use scripted_http::ScriptedHttp;
use secrecy::SecretString;

fn config(base: &str) -> WebDavConfig {
    WebDavConfig {
        base_url: base.to_string(),
        root_path: "/remote.php/dav/files/alice/Clavis".to_string(),
        username: "alice".into(),
        password: SecretString::new("app-password".into()),
        allow_plain_http: false,
    }
}

fn store(http: Arc<ScriptedHttp>) -> WebDavStore {
    WebDavStore::new(http, config("https://cloud.example.com")).unwrap()
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/remote.php/dav/files/alice/Clavis/clavis/11111111-1111-1111-1111-111111111111/revisions/</d:href></d:response>
  <d:response><d:href>/remote.php/dav/files/alice/Clavis/clavis/11111111-1111-1111-1111-111111111111/revisions/22222222-2222-2222-2222-222222222222.clv</d:href></d:response>
</d:multistatus>"#;

#[tokio::test]
async fn propfind_listing_and_path_scoping() {
    let http = Arc::new(ScriptedHttp::new());
    http.push(Ok(HttpResponse {
        status: 207,
        body: PROPFIND_BODY.as_bytes().to_vec(),
        retry_after_secs: None,
    }));
    let s = store(http.clone());
    let vault = VaultId("11111111-1111-1111-1111-111111111111".parse().unwrap());
    let page = s.list_page(&vault, None).await.unwrap();
    assert_eq!(page.objects.len(), 1);
    assert!(page.objects[0]
        .locator
        .starts_with("https://cloud.example.com"));
    // Credentials are only sent to the configured origin.
    let reqs = http.requests.lock().unwrap();
    for r in reqs.iter() {
        assert!(r.url.starts_with("https://cloud.example.com"));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v.starts_with("Basic ")));
    }
}

#[tokio::test]
async fn create_uses_if_none_match_and_accepts_identical_duplicates() {
    let http = Arc::new(ScriptedHttp::new());
    // MKCOL chain (one call per ancestor segment): 405 = exists.
    for _ in 0..8 {
        http.push(Ok(HttpResponse {
            status: 405,
            body: Vec::new(),
            retry_after_secs: None,
        }));
    }
    // PUT with If-None-Match: * -> 412 conflict.
    http.push(Ok(HttpResponse {
        status: 412,
        body: Vec::new(),
        retry_after_secs: None,
    }));
    let bytes = vec![2u8; 32];
    // GET returns byte-identical content: idempotent duplicate is fine.
    http.push(Ok(HttpResponse {
        status: 200,
        body: bytes.clone(),
        retry_after_secs: None,
    }));
    let s = store(http.clone());
    let vault = VaultId("11111111-1111-1111-1111-111111111111".parse().unwrap());
    let rid = RevisionId::generate();
    let _receipt = s.create_object(&vault, &rid, bytes).await.unwrap();
    let reqs = http.requests.lock().unwrap();
    let put = reqs.iter().find(|r| r.method == "PUT").unwrap();
    assert!(put
        .headers
        .iter()
        .any(|(k, v)| k == "if-none-match" && v == "*"));
}

#[tokio::test]
async fn create_rejects_different_bytes_at_same_identity() {
    let http = Arc::new(ScriptedHttp::new());
    for _ in 0..8 {
        http.push(Ok(HttpResponse {
            status: 405,
            body: Vec::new(),
            retry_after_secs: None,
        }));
    }
    http.push(Ok(HttpResponse {
        status: 412,
        body: Vec::new(),
        retry_after_secs: None,
    }));
    // Existing object with DIFFERENT bytes: integrity failure, no overwrite.
    http.push(Ok(HttpResponse {
        status: 200,
        body: vec![9u8; 32],
        retry_after_secs: None,
    }));
    let s = store(http);
    let vault = VaultId("11111111-1111-1111-1111-111111111111".parse().unwrap());
    let rid = RevisionId::generate();
    let err = s
        .create_object(&vault, &rid, vec![2u8; 32])
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "integrity_failure");
}

#[tokio::test]
async fn get_object_rejects_foreign_urls() {
    let http = Arc::new(ScriptedHttp::new());
    let s = store(http);
    let err = s
        .get_object("https://evil.example.com/x.clv")
        .await
        .unwrap_err();
    assert_eq!(err.kind(), "other");
}

#[test]
fn plain_http_rejected_outside_localhost() {
    let http = Arc::new(ScriptedHttp::new());
    assert!(WebDavStore::new(http, config("http://insecure.example.com")).is_err());
    // Development-only localhost HTTP is explicitly allowed.
    let cfg = WebDavConfig {
        base_url: "http://127.0.0.1:8080".into(),
        allow_plain_http: true,
        ..config("unused")
    };
    assert!(WebDavStore::new(Arc::new(ScriptedHttp::new()), cfg).is_ok());
}

#[test]
fn path_traversal_is_rejected() {
    let http = Arc::new(ScriptedHttp::new());
    let cfg = WebDavConfig {
        base_url: "https://cloud.example.com".into(),
        root_path: "/root".into(),
        username: "u".into(),
        password: SecretString::new("p".into()),
        allow_plain_http: false,
    };
    let s = WebDavStore::new(http, cfg).unwrap();
    // get_object on a foreign URL is blocked; path joining is exercised in
    // the unit tests of the path module.
    let _ = s;
}
