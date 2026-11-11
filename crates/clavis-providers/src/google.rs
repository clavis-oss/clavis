//! Google Drive adapter (`drive.file` scope; visible app-created files).
//! Filenames: `clavis-<vault_id>-<revision_id>.clv`. Duplicate names are
//! resolved by examining all matching objects; only byte-identical
//! duplicates for a revision ID are accepted.

use std::sync::Mutex;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use crate::oauth::{form_urlencoded, urlencode, HttpTransport, OAuthConfig, SyncHttpError};
use crate::ProviderKind;
use clavis_core::ids::{RevisionId, VaultId};
use clavis_sync::transport::{digest, Page, RemoteObject, RemoteStore, SyncError, UploadReceipt};

pub struct GoogleDriveStore {
    pub transport: std::sync::Arc<dyn HttpTransport>,
    pub config: OAuthConfig,
    tokens: Mutex<Option<SecretString>>,
}

impl GoogleDriveStore {
    pub fn new(transport: std::sync::Arc<dyn HttpTransport>, config: OAuthConfig) -> Self {
        GoogleDriveStore {
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

    fn file_name(vault_id: &VaultId, revision_id: &RevisionId) -> String {
        format!("clavis-{}-{}.clv", vault_id, revision_id)
    }
}

pub(crate) fn map_status(resp: &crate::oauth::HttpResponse) -> Result<(), SyncError> {
    match resp.status {
        200..=299 => Ok(()),
        401 => Err(SyncError::Unauthorized),
        403 => Err(SyncError::Unauthorized),
        408 | 500..=504 => Err(SyncError::Offline),
        429 => Err(SyncError::RateLimited {
            retry_after: resp.retry_after_secs.map(std::time::Duration::from_secs),
        }),
        507 => Err(SyncError::QuotaExceeded),
        _ => Err(SyncError::OtherSanitized("storage request failed")),
    }
}

#[async_trait]
impl RemoteStore for GoogleDriveStore {
    async fn list_page(&self, vault_id: &VaultId, cursor: Option<&str>) -> Result<Page, SyncError> {
        let prefix = format!("clavis-{}-", vault_id);
        let q = format!("name contains '{}' and trashed = false", prefix);
        let mut url = format!(
            "https://www.googleapis.com/drive/v3/files?q={}&pageSize=100&fields=nextPageToken,files(id,name,size,md5Checksum)",
            urlencode(&q)
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&pageToken={}", urlencode(c)));
        }
        let resp = self.call("GET", url, Vec::new(), None).await?;
        let json: Value = serde_json::from_slice(&resp.body)
            .map_err(|_| SyncError::OtherSanitized("malformed listing"))?;
        let mut objects = Vec::new();
        if let Some(files) = json["files"].as_array() {
            for f in files {
                let name = f["name"].as_str().unwrap_or_default().to_string();
                let rid_str = name
                    .strip_prefix(&prefix)
                    .and_then(|s| s.strip_suffix(".clv"));
                let Some(rid_str) = rid_str else { continue };
                let Ok(revision_id) = rid_str.parse::<uuid::Uuid>() else {
                    continue;
                };
                objects.push(RemoteObject {
                    locator: f["id"].as_str().unwrap_or_default().to_string(),
                    revision_id: RevisionId(revision_id),
                    size: f["size"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .or_else(|| f["size"].as_u64())
                        .unwrap_or(0),
                    digest: None,
                });
            }
        }
        Ok(Page {
            objects,
            next_cursor: json["nextPageToken"].as_str().map(str::to_string),
        })
    }

    async fn get_object(&self, locator: &str) -> Result<Vec<u8>, SyncError> {
        let url = format!(
            "https://www.googleapis.com/drive/v3/files/{}?alt=media",
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
        let name = Self::file_name(vault_id, revision_id);
        let boundary = "clavis-upload-boundary-7f3a";
        let metadata = serde_json::json!({ "name": name });
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{}\r\ncontent-type: application/json\r\n\r\n{}\r\n--{}\r\ncontent-type: application/octet-stream\r\n\r\n", boundary, metadata, boundary).as_bytes());
        body.extend_from_slice(&bytes);
        body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
        let url =
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart".to_string();
        let resp = self
            .call(
                "POST",
                url,
                body,
                Some(&format!("multipart/related; boundary={}", boundary)),
            )
            .await?;
        // A response without a file id is a failed upload.
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

/// Reusable token refresh for Google (also used by CLI/desktop reconnect).
pub async fn refresh_access_token(
    transport: &dyn HttpTransport,
    config: &OAuthConfig,
    refresh_token: &SecretString,
) -> Result<SecretString, SyncError> {
    let body = form_urlencoded(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.expose_secret()),
        ("client_id", &config.client_id),
    ]);
    let resp = transport
        .execute(crate::oauth::HttpRequest {
            method: "POST",
            url: config.token_url.clone(),
            headers: vec![(
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: body.into_bytes(),
        })
        .await
        .map_err(|e| match e {
            SyncHttpError::Offline => SyncError::Offline,
            SyncHttpError::Other(_) => SyncError::OtherSanitized("refresh failed"),
        })?;
    if resp.status != 200 {
        return Err(map_status(&resp).unwrap_err());
    }
    let json: Value = serde_json::from_slice(&resp.body)
        .map_err(|_| SyncError::OtherSanitized("malformed refresh response"))?;
    Ok(SecretString::new(
        json["access_token"]
            .as_str()
            .unwrap_or_default()
            .to_string()
            .into(),
    ))
}

/// Ensure the provider kind matches this adapter's registration.
pub fn provider_kind() -> ProviderKind {
    ProviderKind::GoogleDrive
}
