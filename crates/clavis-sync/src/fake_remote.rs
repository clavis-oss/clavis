//! Deterministic fake remote for contract tests. Emulates: pagination,
//! duplicate listings, delayed visibility, cursor expiry, dropped upload
//! responses, byte-size limits and scripted failures.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use clavis_core::ids::{RevisionId, VaultId};

use crate::transport::{
    digest, object_key, Page, RemoteObject, RemoteStore, SyncError, UploadReceipt,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptedFailure {
    Offline,
    Unauthorized,
    QuotaExceeded,
    RateLimited(Option<u64>),
    Integrity,
    DroppedUpload,
    None,
}

#[derive(Clone, Debug, Default)]
pub struct FakeRemoteConfig {
    pub page_size: usize,
    /// Objects become visible only after this many `list_page` calls.
    pub visibility_delay: usize,
    /// Listing a second page invalidates the first cursor (expiry).
    pub cursor_expires: bool,
    /// Serve duplicate listings.
    pub duplicate_listings: bool,
    /// Reject uploads larger than this.
    pub max_body: Option<usize>,
}

struct Inner {
    objects: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    list_calls: AtomicUsize,
    /// Scripted failure consumed per operation call.
    failures: Mutex<Vec<ScriptedFailure>>,
}

pub struct FakeRemote {
    config: FakeRemoteConfig,
    inner: Inner,
    pub uploads_verified: AtomicBool,
    pub upload_count: AtomicUsize,
}

impl FakeRemote {
    pub fn new(config: FakeRemoteConfig) -> Self {
        FakeRemote {
            config,
            uploads_verified: AtomicBool::new(false),
            upload_count: AtomicUsize::new(0),
            inner: Inner {
                objects: Mutex::new(BTreeMap::new()),
                list_calls: AtomicUsize::new(0),
                failures: Mutex::new(Vec::new()),
            },
        }
    }

    pub fn push_object(&self, vault_id: &VaultId, revision_id: &RevisionId, bytes: Vec<u8>) {
        self.inner
            .objects
            .lock()
            .unwrap()
            .insert((vault_id.to_string(), revision_id.to_string()), bytes);
    }

    pub fn push_failure(&self, f: ScriptedFailure) {
        self.inner.failures.lock().unwrap().push(f);
    }

    pub fn unique_revision_count(&self, vault_id: &VaultId, revision_id: &RevisionId) -> usize {
        self.inner
            .objects
            .lock()
            .unwrap()
            .keys()
            .filter(|(v, r)| v == &vault_id.to_string() && r == &revision_id.to_string())
            .count()
    }

    pub fn object_count(&self) -> usize {
        self.inner.objects.lock().unwrap().len()
    }

    fn next_failure(&self) -> ScriptedFailure {
        let mut q = self.inner.failures.lock().unwrap();
        if q.is_empty() {
            ScriptedFailure::None
        } else {
            q.remove(0)
        }
    }
}

#[async_trait]
impl RemoteStore for FakeRemote {
    async fn list_page(&self, vault_id: &VaultId, cursor: Option<&str>) -> Result<Page, SyncError> {
        match self.next_failure() {
            ScriptedFailure::Offline => return Err(SyncError::Offline),
            ScriptedFailure::Unauthorized => return Err(SyncError::Unauthorized),
            ScriptedFailure::QuotaExceeded => return Err(SyncError::QuotaExceeded),
            ScriptedFailure::RateLimited(d) => {
                return Err(SyncError::RateLimited {
                    retry_after: d.map(std::time::Duration::from_secs),
                })
            }
            _ => {}
        }
        // Cursor expiry: a cursor other than "page:0" is invalid once a
        // newer listing has started.
        if let Some(c) = cursor {
            if self.config.cursor_expires && c != "page:0" {
                return Err(SyncError::OtherSanitized("cursor expired"));
            }
        }
        let calls = self.inner.list_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let visible = calls > self.config.visibility_delay;
        let mut objects: Vec<RemoteObject> = Vec::new();
        if visible {
            for ((v, r), bytes) in self.inner.objects.lock().unwrap().iter() {
                if v != &vault_id.to_string() {
                    continue;
                }
                let obj = RemoteObject {
                    locator: object_key(
                        &VaultId(v.parse().unwrap()),
                        &RevisionId(r.parse().unwrap()),
                    ),
                    revision_id: RevisionId(r.parse().unwrap()),
                    size: bytes.len() as u64,
                    digest: Some(digest(bytes)),
                };
                if self.config.duplicate_listings {
                    objects.push(obj.clone());
                }
                objects.push(obj);
            }
        }
        let page_size = if self.config.page_size == 0 {
            usize::MAX
        } else {
            self.config.page_size
        };
        let start = cursor
            .and_then(|c| c.strip_prefix("page:"))
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);
        let end = (start + page_size).min(objects.len());
        let next_cursor = if end < objects.len() {
            Some(format!("page:{}", end))
        } else {
            None
        };
        Ok(Page {
            objects: objects[start..end].to_vec(),
            next_cursor,
        })
    }

    async fn get_object(&self, locator: &str) -> Result<Vec<u8>, SyncError> {
        let scripted = self.next_failure();
        // Revision ID is the file-name stem of the logical object key.
        let rid = locator
            .rsplit('/')
            .next()
            .and_then(|s| s.strip_suffix(".clv"))
            .ok_or(SyncError::OtherSanitized("object not found"))?;
        let bytes = self
            .inner
            .objects
            .lock()
            .unwrap()
            .iter()
            .find(|((_, r), _)| r == rid)
            .map(|(_, b)| b.clone())
            .ok_or(SyncError::OtherSanitized("object not found"))?;
        match scripted {
            ScriptedFailure::Offline => return Err(SyncError::Offline),
            ScriptedFailure::Integrity => {
                let mut bad = bytes;
                if let Some(last) = bad.last_mut() {
                    *last ^= 0xff;
                }
                return Ok(bad);
            }
            _ => {}
        }
        Ok(bytes)
    }

    async fn create_object(
        &self,
        vault_id: &VaultId,
        revision_id: &RevisionId,
        bytes: Vec<u8>,
    ) -> Result<UploadReceipt, SyncError> {
        match self.next_failure() {
            ScriptedFailure::Offline => return Err(SyncError::Offline),
            ScriptedFailure::QuotaExceeded => return Err(SyncError::QuotaExceeded),
            ScriptedFailure::Unauthorized => return Err(SyncError::Unauthorized),
            ScriptedFailure::RateLimited(d) => {
                return Err(SyncError::RateLimited {
                    retry_after: d.map(std::time::Duration::from_secs),
                })
            }
            ScriptedFailure::DroppedUpload => {
                // The bytes are stored but the response is lost; a retry must
                // be idempotent and not fork content.
                self.inner.objects.lock().unwrap().insert(
                    (vault_id.to_string(), revision_id.to_string()),
                    bytes.clone(),
                );
                return Err(SyncError::OtherSanitized("upload response lost"));
            }
            _ => {}
        }
        if let Some(max) = self.config.max_body {
            if bytes.len() > max {
                return Err(SyncError::OtherSanitized("response-body size limit"));
            }
        } // Same identity with different bytes is an integrity error.
        if let Some(existing) = self
            .inner
            .objects
            .lock()
            .unwrap()
            .get(&(vault_id.to_string(), revision_id.to_string()))
        {
            if digest(existing) != digest(&bytes) {
                return Err(SyncError::IntegrityFailure);
            }
        }
        self.inner.objects.lock().unwrap().insert(
            (vault_id.to_string(), revision_id.to_string()),
            bytes.clone(),
        );
        self.upload_count.fetch_add(1, Ordering::SeqCst);
        Ok(UploadReceipt {
            locator: object_key(vault_id, revision_id),
            digest: digest(&bytes),
        })
    }
}
