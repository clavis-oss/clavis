//! OneDrive adapter: delegated `Files.ReadWrite.AppFolder` against
//! `/me/drive/special/approot` with stable item IDs, opaque next-link
//! following with host validation, and conflict-behavior=fail uploads so
//! immutable objects are never overwritten.

use std::sync::Mutex;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use crate::google::map_status;
use crate::oauth::{urlencode, HttpTransport, OAuthConfig, SyncHttpError};
use clavis_core::ids::{RevisionId, VaultId};
use clavis_sync::transport::{digest, Page, RemoteObject, RemoteStore, SyncError, UploadReceipt};

const GRAPH_HOST: &str = "https://graph.microsoft.com";

pub struct OneDriveStore {
    pub transport: std::sync::Arc<dyn HttpTransport>,
    pub config: OAuthConfig,
    tokens: Mutex<Option<SecretString>>,
}

impl OneDriveStore {
    pub fn new(transport: std::sync::Arc<dyn HttpTransport>, config: OAuthConfig) -> Self {
        OneDriveStore {
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
        method: &'static str,
        url: String,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<crate::oauth::HttpResponse, SyncError> {
        let mut headers = vec![(
            "authorization".to_string(),
            format!("Bearer {}", self.token()?),
        )];
        if let Some(ct) = content_type {
            headers.push(("content-type".to_string(), ct.to_string()));
        }
        let resp = self
            .transport
            .execute(crate::oauth::HttpRequest {
                method,
                url,
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

    fn revisions_dir(vault_id: &VaultId) -> String {
        format!("clavis/{}/revisions", vault_id)
    }
}

/// Next links are provider-supplied URLs; only approved origins may be
/// followed and credentials are never forwarded elsewhere.
fn validate_next_link(url: &str) -> Result<(), SyncError> {
    if url.starts_with(GRAPH_HOST) {
        Ok(())
    } else {
        Err(SyncError::OtherSanitized("unapproved continuation host"))
    }
}

#[async_trait]
impl RemoteStore for OneDriveStore {
    async fn list_page(&self, vault_id: &VaultId, cursor: Option<&str>) -> Result<Page, SyncError> {
        let url = match cursor {
            None => format!(
                "{}/me/drive/special/approot:/{}:/children?$top=100",
                GRAPH_HOST,
                Self::revisions_dir(vault_id)
                    .split('/')
                    .map(urlencode)
                    .collect::<Vec<_>>()
                    .join("/")
            ),
            Some(link) => {
                validate_next_link(link)?;
                link.to_string()
            }
        };
        let resp = self.call("GET", url, Vec::new(), None).await?;
        let json: Value = serde_json::from_slice(&resp.body)
            .map_err(|_| SyncError::OtherSanitized("malformed listing"))?;
        let mut objects = Vec::new();
        if let Some(items) = json["value"].as_array() {
            for it in items {
                let name = it["name"].as_str().unwrap_or_default();
                let Some(rid_str) = name.strip_suffix(".clv") else {
                    continue;
                };
                let Ok(revision_id) = rid_str.parse::<uuid::Uuid>() else {
                    continue;
                };
                objects.push(RemoteObject {
                    locator: it["id"].as_str().unwrap_or_default().to_string(),
                    revision_id: RevisionId(revision_id),
                    size: it["size"].as_u64().unwrap_or(0),
                    digest: None,
                });
            }
        }
        let next = json["@odata.nextLink"].as_str().map(str::to_string);
        if let Some(n) = &next {
            validate_next_link(n)?;
        }
        Ok(Page {
            objects,
            next_cursor: next,
        })
    }

    async fn get_object(&self, locator: &str) -> Result<Vec<u8>, SyncError> {
        let url = format!(
            "{}/me/drive/items/{}/content",
            GRAPH_HOST,
            urlencode(locator)
        );
        let resp = self.call("GET", url, Vec::new(), None).await?;
        Ok(resp.body)
    }

    async fn create_object(
        &self,
        vault_id: &VaultId,
        revision_id: &RevisionId,
        bytes: Vec<u8>,
    ) -> Result<UploadReceipt, SyncError> {
        let path = format!("clavis/{}/revisions/{}.clv", vault_id, revision_id);
        let encoded: String = path.split('/').map(urlencode).collect::<Vec<_>>().join("/");
        let url = format!(
            "{}/me/drive/special/approot:/{encoded}:/content?@microsoft.graph.conflictBehavior=fail",
            GRAPH_HOST
        );
        let resp = self
            .call("PUT", url, bytes.clone(), Some("application/octet-stream"))
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
