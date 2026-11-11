mod scripted_http;

use std::sync::Arc;

use clavis_core::ids::{RevisionId, VaultId};
use clavis_providers::oauth::{onedrive_config, HttpRequest};
use clavis_providers::onedrive::OneDriveStore;
use clavis_sync::transport::{digest, RemoteStore};
use scripted_http::ScriptedHttp;
use secrecy::SecretString;

fn store(http: Arc<ScriptedHttp>) -> OneDriveStore {
    let s = OneDriveStore::new(http, onedrive_config("test-client", 0));
    s.set_access_token(SecretString::new("test-token".into()));
    s
}

#[tokio::test]
async fn list_parses_children_and_next_links() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(
        200,
        r#"{"value":[{"id":"item-1","name":"aaaaaaa1-1111-1111-1111-111111111111.clv","size":100}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/me/drive/special/approot:/children?$top=100&$skiptoken=abc"}"#,
    );
    http.push_json(200, r#"{"value":[{"id":"item-2","name":"aaaaaaa1-1111-1111-1111-111111111112.clv","size":200}]}"#);
    let s = store(http.clone());
    let vault = VaultId("aaaaaaaa-1111-1111-1111-111111111111".parse().unwrap());
    let page1 = s.list_page(&vault, None).await.unwrap();
    assert_eq!(page1.objects.len(), 1);
    assert_eq!(page1.objects[0].locator, "item-1");
    let page2 = s
        .list_page(&vault, page1.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(page2.objects.len(), 1);
    // The next link was followed only because it is an approved origin.
    let req = http.last_request();
    assert!(req.url.starts_with("https://graph.microsoft.com/"));
}

#[tokio::test]
async fn unapproved_next_link_host_is_rejected() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(
        200,
        r#"{"value":[],"@odata.nextLink":"https://evil.example.com/children"}"#,
    );
    let s = store(http);
    let vault = VaultId("aaaaaaaa-1111-1111-1111-111111111111".parse().unwrap());
    let err = s.list_page(&vault, None).await.unwrap_err();
    assert_eq!(err.kind(), "other");
}

#[tokio::test]
async fn upload_uses_conflict_behavior_fail() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(201, r#"{"id":"new-item","name":"x.clv","size":128}"#);
    let s = store(http.clone());
    let vault = VaultId("aaaaaaaa-1111-1111-1111-111111111111".parse().unwrap());
    let rid = RevisionId::generate();
    let bytes = vec![3u8; 128];
    let receipt = s.create_object(&vault, &rid, bytes.clone()).await.unwrap();
    assert_eq!(receipt.digest, digest(&bytes));
    let req: HttpRequest = http.last_request();
    assert!(
        req.url.contains("conflictBehavior=fail"),
        "immutable objects must never be silently overwritten"
    );
    assert_eq!(req.method, "PUT");
}

#[tokio::test]
async fn unauthorized_maps_to_reauth() {
    let http = Arc::new(ScriptedHttp::new());
    http.push_json(401, r#"{"error":{"code":"InvalidAuthenticationToken"}}"#);
    let s = store(http);
    let vault = VaultId("aaaaaaaa-1111-1111-1111-111111111111".parse().unwrap());
    let err = s.list_page(&vault, None).await.unwrap_err();
    assert_eq!(err.kind(), "unauthorized");
}
