pub mod path;
pub mod xml;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::oauth::{HttpTransport, SyncHttpError};
use clavis_core::error::CoreError;
use clavis_core::ids::{RevisionId, VaultId};
use clavis_sync::transport::{digest, Page, RemoteObject, RemoteStore, SyncError, UploadReceipt};

/// WebDAV connection. Credentials are device-local encrypted data, never
/// OTP vault content. HTTPS is the default; a private/LAN endpoint is
/// allowed because the user explicitly selected their own storage.
#[derive(Clone, Debug)]
pub struct WebDavConfig {
    pub base_url: String,
    /// Server-side path of the user-selected remote root.
    pub root_path: String,
    pub username: String,
    pub password: SecretString,
    /// Development-only plain HTTP for localhost testing.
    pub allow_plain_http: bool,
}

pub struct WebDavStore {
    pub transport: std::sync::Arc<dyn HttpTransport>,
    pub config: WebDavConfig,
}

fn map_webdav_status(resp: &crate::oauth::HttpResponse) -> Result<(), SyncError> {
    match resp.status {
        401 => Err(SyncError::Unauthorized),
        408 => Err(SyncError::Offline),
        429 => Err(SyncError::RateLimited {
            retry_after: resp.retry_after_secs.map(std::time::Duration::from_secs),
        }),
        507 => Err(SyncError::QuotaExceeded),
        200..=499 => {
            // Remaining 4xx are passed through so callers can interpret
            // them (404 missing, 405 exists, 412 precondition, 409
            // conflict).
            Ok(())
        }
        500..=504 => Err(SyncError::Offline),
        _ => Err(SyncError::OtherSanitized("storage request failed")),
    }
}

impl WebDavStore {
    pub fn new(
        transport: std::sync::Arc<dyn HttpTransport>,
        config: WebDavConfig,
    ) -> Result<Self, CoreError> {
        if !config.base_url.starts_with("https://")
            && !(config.allow_plain_http && config.base_url.starts_with("http://localhost:")
                || config.allow_plain_http && config.base_url.starts_with("http://127.0.0.1:"))
        {
            return Err(CoreError::InvalidInput(
                "HTTPS is required (plain HTTP is development-only for localhost)",
            ));
        }
        Ok(WebDavStore { transport, config })
    }

    async fn call(
        &self,
        method: &'static str,
        url: &str,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<crate::oauth::HttpResponse, SyncError> {
        let mut headers = headers;
        headers.push((
            "authorization".to_string(),
            format!(
                "Basic {}",
                crate::oauth::basic_auth(
                    &self.config.username,
                    self.config.password.expose_secret()
                )
            ),
        ));
        let resp = self
            .transport
            .execute(crate::oauth::HttpRequest {
                method,
                url: url.to_string(),
                headers,
                body,
            })
            .await
            .map_err(|e| match e {
                SyncHttpError::Offline => SyncError::Offline,
                SyncHttpError::Other(_) => SyncError::OtherSanitized("request failed"),
            })?;
        map_webdav_status(&resp)?;
        Ok(resp)
    }

    fn object_url(
        &self,
        vault_id: &VaultId,
        revision_id: &RevisionId,
    ) -> Result<String, SyncError> {
        let rel = path::join_beneath_root(
            &self.config.root_path,
            &format!("clavis/{}/revisions/{}.clv", vault_id, revision_id),
        )
        .map_err(|_| SyncError::OtherSanitized("invalid remote path"))?;
        Ok(path::url_from_base(&self.config.base_url, &rel))
    }
}

#[async_trait]
impl RemoteStore for WebDavStore {
    async fn list_page(
        &self,
        vault_id: &VaultId,
        _cursor: Option<&str>,
    ) -> Result<Page, SyncError> {
        let dir = path::join_beneath_root(
            &self.config.root_path,
            &format!("clavis/{}/revisions", vault_id),
        )
        .map_err(|_| SyncError::OtherSanitized("invalid remote path"))?;
        let url = path::url_from_base(&self.config.base_url, &dir);
        let resp = self
            .call(
                "PROPFIND",
                &url,
                Vec::new(),
                vec![
                    ("depth".to_string(), "1".to_string()),
                    ("content-type".to_string(), "application/xml".to_string()),
                ],
            )
            .await?;
        if resp.status == 404 {
            // Folder not created yet: empty listing.
            return Ok(Page::default());
        }
        let hrefs = xml::parse_multistatus_hrefs(&resp.body)
            .map_err(|_| SyncError::OtherSanitized("malformed PROPFIND response"))?;
        let base_dir = format!("{}/", dir.trim_end_matches('/'));
        let mut objects = Vec::new();
        for href in hrefs {
            let decoded = percent_decode(&href);
            let rel_to_dir = decoded
                .strip_prefix(&base_dir)
                .map(str::to_string)
                .unwrap_or_default();
            let Some(name) = rel_to_dir.split('/').next_back().filter(|s| !s.is_empty()) else {
                continue;
            };
            let Some(rid_str) = name.strip_suffix(".clv") else {
                continue;
            };
            let Ok(revision_id) = rid_str.parse::<uuid::Uuid>() else {
                continue;
            };
            let obj_url = path::url_from_base(&self.config.base_url, &decoded);
            objects.push(RemoteObject {
                locator: obj_url,
                revision_id: RevisionId(revision_id),
                size: 0,
                digest: None,
            });
        }
        Ok(Page {
            objects,
            next_cursor: None,
        })
    }

    async fn get_object(&self, locator: &str) -> Result<Vec<u8>, SyncError> {
        // Only URLs beneath the configured base may be fetched.
        if !locator.starts_with(self.config.base_url.as_str()) {
            return Err(SyncError::OtherSanitized("unapproved object URL"));
        }
        let resp = self.call("GET", locator, Vec::new(), Vec::new()).await?;
        if resp.status == 404 {
            return Err(SyncError::OtherSanitized("object not found"));
        }
        Ok(resp.body)
    }

    async fn create_object(
        &self,
        vault_id: &VaultId,
        revision_id: &RevisionId,
        bytes: Vec<u8>,
    ) -> Result<UploadReceipt, SyncError> {
        // Ensure the collection chain exists (idempotent; 405 = exists).
        let rev_dir = path::join_beneath_root(
            &self.config.root_path,
            &format!("clavis/{}/revisions", vault_id),
        )
        .map_err(|_| SyncError::OtherSanitized("invalid remote path"))?;
        let mut ancestors = String::new();
        for seg in rev_dir.split('/').filter(|s| !s.is_empty()) {
            if !ancestors.ends_with('/') && !ancestors.is_empty() {
                ancestors.push('/');
            }
            ancestors.push_str(seg);
            let url = path::url_from_base(&self.config.base_url, &ancestors);
            let resp = self.call("MKCOL", &url, Vec::new(), Vec::new()).await?;
            let _ = resp;
        }
        let url = self.object_url(vault_id, revision_id)?;
        let resp = self
            .call(
                "PUT",
                &url,
                bytes.clone(),
                vec![("if-none-match".to_string(), "*".to_string())],
            )
            .await?;
        match resp.status {
            201 | 204 | 200 => {}
            412 | 405 | 409 => {
                // Object exists: accept only byte-identical duplicates.
                let existing = self.call("GET", &url, Vec::new(), Vec::new()).await?;
                if existing.status == 200 && existing.body == bytes {
                    return Ok(UploadReceipt {
                        locator: url,
                        digest: digest(&bytes),
                    });
                }
                return Err(SyncError::IntegrityFailure);
            }
            other => {
                let _ = other;
                return Err(SyncError::OtherSanitized("upload failed"));
            }
        }
        Ok(UploadReceipt {
            locator: url,
            digest: digest(&bytes),
        })
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                16,
            ) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
