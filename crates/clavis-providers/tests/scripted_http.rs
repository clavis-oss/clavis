#![allow(dead_code)] // shared helpers are used by only some test binaries
//! Shared scripted HTTP transport for adapter contract tests. Responses are
//! sanitized fixtures; no real network access happens in CI.

#[allow(dead_code)]
use clavis_providers::oauth::{HttpRequest, HttpResponse, HttpTransport, SyncHttpError};
use std::sync::Mutex;

pub struct ScriptedHttp {
    pub requests: Mutex<Vec<HttpRequest>>,
    pub responses: Mutex<Vec<Result<HttpResponse, SyncHttpError>>>,
}

impl ScriptedHttp {
    pub fn new() -> Self {
        ScriptedHttp {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(Vec::new()),
        }
    }

    pub fn push_json(&self, status: u16, body: &str) {
        self.responses.lock().unwrap().push(Ok(HttpResponse {
            status,
            body: body.as_bytes().to_vec(),
            retry_after_secs: None,
        }));
    }

    pub fn push(&self, r: Result<HttpResponse, SyncHttpError>) {
        self.responses.lock().unwrap().push(r);
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    pub fn last_request(&self) -> HttpRequest {
        self.requests.lock().unwrap().last().unwrap().clone()
    }
}

impl Default for ScriptedHttp {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HttpTransport for ScriptedHttp {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, SyncHttpError> {
        self.requests.lock().unwrap().push(req);
        let mut q = self.responses.lock().unwrap();
        if q.is_empty() {
            return Err(SyncHttpError::Other("no scripted response"));
        }
        q.remove(0)
    }
}
