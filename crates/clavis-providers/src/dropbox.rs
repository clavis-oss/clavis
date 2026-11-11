//! Dropbox adapter: App Folder access with API revision IDs as transport
//! metadata, `mode: add` uploads (never overwrite), list_folder/continue
//! cursors and production-approved scopes.

use std::sync::Mutex;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use crate::google::map_status;
use crate::oauth::{HttpTransport, OAuthConfig, SyncHttpError};
use clavis_core::ids::{RevisionId, VaultId};
use clavis_sync::transport::{digest, Page, RemoteObject, RemoteStore, SyncError, UploadReceipt};

pub struct DropboxStore {
    pub transport: std::sync::Arc<dyn HttpTransport>,
    pub config: OAuthConfig,
    tokens: Mutex<Option<SecretString>>,
}

impl DropboxStore {
    pub fn new(transport: std::sync::Arc<dyn HttpTransport>, config: OAuthConfig) -> Self {
        DropboxStore {
            transport,
            config,
            tokens: Mutex::new(None),
        }
    }

    pub fn set_access_token(&self, token: SecretString) {
        *self.tokens.lock().unwrap() = Some(token);
    }

    fn token(&self) -> Result<String, SyncError> {
        self.tokens
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| t.expose_secret().to_string())
            .ok_or(SyncError::Unauthorized)
    }

    async fn call(
        &self,
        url: &str,
        json_body: Option<Value>,
        api_arg: Option<Value>,
        body: Vec<u8>,
    ) -> Result<crate::oauth::HttpResponse, SyncError> {
        let mut headers = vec![(
            "authorization".to_string(),
            format!("Bearer {}", self.token()?),
        )];
        if let Some(arg) = api_arg {
            headers.push(("dropbox-api-arg".to_string(), arg.to_string()));
            headers.push((
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            ));
        } else if let Some(j) = &json_body {
            headers.push(("content-type".to_string(), "application/json".to_string()));
            return self
                .raw_call(url, j.to_string().into_bytes(), headers)
                .await;
        }
        self.raw_call(url, body, headers).await
    }

    async fn raw_call(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<crate::oauth::HttpResponse, SyncError> {
        let resp = self
            .transport
            .execute(crate::oauth::HttpRequest {
                method: "POST",
                url: url.to_string(),
                headers,
                body,
            })
            .await
            .map_err(|e| match e {
                SyncHttpError::Offline => SyncError::Offline,
                SyncHttpError::Other(_) => SyncError::OtherSanitized("request failed"),
            })?;
        map_status(&resp)?;
        Ok(resp)
    }
}

const LIST_URL: &str = "https://content.dropboxapi.com/2/files/list_folder";
const LIST_CONTINUE_URL: &str = "https://content.dropboxapi.com/2/files/list_folder/continue";
const UPLOAD_URL: &str = "https://content.dropboxapi.com/2/files/upload";
const DOWNLOAD_URL: &str = "https://content.dropboxapi.com/2/files/download";

#[async_trait]
impl RemoteStore for DropboxStore {
    async fn list_page(&self, vault_id: &VaultId, cursor: Option<&str>) -> Result<Page, SyncError> {
        let resp = match cursor {
            None => {
                let body = serde_json::json!({
                    "path": format!("/clavis/{}/revisions", vault_id),
                    "recursive": false,
                    "limit": 100,
                });
                self.call(LIST_URL, Some(body), None, Vec::new()).await?
            }
            Some(c) => {
                let body = serde_json::json!({ "cursor": c });
                self.call(LIST_CONTINUE_URL, Some(body), None, Vec::new())
                    .await?
            }
        };
        let json: Value = serde_json::from_slice(&resp.body)
            .map_err(|_| SyncError::OtherSanitized("malformed listing"))?;
        let mut objects = Vec::new();
        if let Some(entries) = json["entries"].as_array() {
            for e in entries {
                let name = e["name"].as_str().unwrap_or_default();
                let Some(rid_str) = name.strip_suffix(".clv") else {
                    continue;
                };
                let Ok(revision_id) = rid_str.parse::<uuid::Uuid>() else {
                    continue;
                };
                objects.push(RemoteObject {
                    locator: e["id"].as_str().unwrap_or_default().to_string(),
                    revision_id: RevisionId(revision_id),
                    size: e["size"].as_u64().unwrap_or(0),
                    digest: None,
                });
            }
        }
        let next = if json["has_more"].as_bool().unwrap_or(false) {
            json["cursor"].as_str().map(str::to_string)
        } else {
            None
        };
        Ok(Page {
            objects,
            next_cursor: next,
        })
    }

    async fn get_object(&self, locator: &str) -> Result<Vec<u8>, SyncError> {
        let arg = serde_json::json!({ "path": locator });
        let resp = self.call(DOWNLOAD_URL, None, Some(arg), Vec::new()).await?;
        Ok(resp.body)
    }

    async fn create_object(
        &self,
        vault_id: &VaultId,
        revision_id: &RevisionId,
        bytes: Vec<u8>,
    ) -> Result<UploadReceipt, SyncError> {
        let arg = serde_json::json!({
            "path": format!("/clavis/{}/revisions/{}.clv", vault_id, revision_id),
            "mode": "add",
            "autorename": false,
            "mute": true,
        });
        let resp = self
            .call(UPLOAD_URL, None, Some(arg), bytes.clone())
            .await?;
        let json: Value = serde_json::from_slice(&resp.body)
            .map_err(|_| SyncError::OtherSanitized("malformed upload response"))?;
        let locator = json["id"]
            .as_str()
            .ok_or(SyncError::OtherSanitized("malformed upload response"))?
            .to_string();
        Ok(UploadReceipt {
            locator,
            digest: digest(&bytes),
        })
    }
}
