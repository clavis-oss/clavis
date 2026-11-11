pub mod callback;
pub mod credentials;
pub mod pkce;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::ProviderKind;
use clavis_core::error::CoreError;

/// Pending requests are single-use and expire after five minutes.
pub const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// An HTTP transport so the OAuth and adapter code can be tested against
/// recorded responses without real network access.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, SyncHttpError>;
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Retry-After header in seconds when present.
    pub retry_after_secs: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncHttpError {
    #[error("network unreachable")]
    Offline,
    #[error("request failed")]
    Other(&'static str),
}

pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, CoreError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| CoreError::Internal("http client"))?;
        Ok(ReqwestTransport { client })
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new().expect("reqwest client")
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, SyncHttpError> {
        let method = match req.method {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PROPFIND" => reqwest::Method::from_bytes(b"PROPFIND").expect("valid method"),
            "MKCOL" => reqwest::Method::from_bytes(b"MKCOL").expect("valid method"),
            _ => return Err(SyncHttpError::Other("unsupported method")),
        };
        let mut r = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            r = r.header(k, v);
        }
        if !req.body.is_empty() {
            r = r.body(req.body.clone());
        }
        let resp = r.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                SyncHttpError::Offline
            } else {
                SyncHttpError::Other("request failed")
            }
        })?;
        let status = resp.status().as_u16();
        let retry_after_secs = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let body = resp
            .bytes()
            .await
            .map_err(|_| SyncHttpError::Other("body read"))?;
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
            retry_after_secs,
        })
    }
}

/// OAuth client configuration for one provider. Public client: PKCE, no
/// client secret as a security boundary.
#[derive(Clone, Debug)]
pub struct OAuthConfig {
    pub provider: ProviderKind,
    pub client_id: String,
    pub authorize_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    /// Loopback redirect used on desktop (e.g. http://127.0.0.1:port/callback).
    pub redirect_uri: String,
}

pub fn google_config(client_id: &str, port: u16) -> OAuthConfig {
    OAuthConfig {
        provider: ProviderKind::GoogleDrive,
        client_id: client_id.to_string(),
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        token_url: "https://oauth2.googleapis.com/token".into(),
        scopes: vec![
            "https://www.googleapis.com/auth/drive.file".into(),
            "openid".into(),
            "email".into(),
        ],
        redirect_uri: format!("http://127.0.0.1:{port}/callback"),
    }
}

pub fn onedrive_config(client_id: &str, port: u16) -> OAuthConfig {
    OAuthConfig {
        provider: ProviderKind::OneDrive,
        client_id: client_id.to_string(),
        authorize_url: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize".into(),
        token_url: "https://login.microsoftonline.com/consumers/oauth2/v2.0/token".into(),
        scopes: vec!["Files.ReadWrite.AppFolder".into(), "offline_access".into()],
        redirect_uri: format!("http://127.0.0.1:{port}/callback"),
    }
}

pub fn dropbox_config(client_id: &str, port: u16) -> OAuthConfig {
    OAuthConfig {
        provider: ProviderKind::Dropbox,
        client_id: client_id.to_string(),
        authorize_url: "https://www.dropbox.com/oauth2/authorize".into(),
        token_url: "https://api.dropboxapi.com/oauth2/token".into(),
        scopes: vec![
            "files.content.write".into(),
            "files.content.read".into(),
            "account_info.read".into(),
        ],
        redirect_uri: format!("http://127.0.0.1:{port}/callback"),
    }
}

/// A pending authorization: state, PKCE verifier and redirect, single-use,
/// expiring after five minutes.
pub struct PendingAuthorization {
    pub id: String,
    pub config: OAuthConfig,
    pub state: String,
    pub code_verifier: SecretString,
    pub redirect_uri: String,
    pub created_unix: u64,
}

impl std::fmt::Debug for PendingAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PendingAuthorization({})", self.id)
    }
}

#[derive(Default)]
pub struct PendingStore {
    next: Mutex<u64>,
    entries: Mutex<BTreeMap<String, PendingAuthorization>>,
}

impl PendingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin a connect: build the authorization URL with PKCE S256 and an
    /// anti-CSRF state. The external browser (never an embedded WebView)
    /// opens this URL.
    pub fn begin(&self, config: OAuthConfig, now_unix: u64) -> (String, String) {
        let state = pkce::random_token(24);
        let verifier = pkce::random_token(64);
        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            format!("pending-{}", *n)
        };
        let mut url = format!(
            "{}?response_type=code&client_id={}&state={}&code_challenge={}&code_challenge_method=S256&redirect_uri={}",
            config.authorize_url,
            urlencode(&config.client_id),
            urlencode(&state),
            urlencode(&pkce::challenge_s256(&SecretString::new(verifier.clone().into()))),
            urlencode(&config.redirect_uri),
        );
        if !config.scopes.is_empty() {
            url.push_str(&format!("&scope={}", urlencode(&config.scopes.join(" "))));
        }
        if config.provider == ProviderKind::Dropbox {
            url.push_str("&token_access_type=offline");
        }
        let pending = PendingAuthorization {
            id: id.clone(),
            config: config.clone(),
            state: state.clone(),
            code_verifier: SecretString::new(verifier.into()),
            redirect_uri: config.redirect_uri.clone(),
            created_unix: now_unix,
        };
        self.entries.lock().unwrap().insert(id.clone(), pending);
        (id, url)
    }

    /// Complete a connect: validate state and single use, then exchange the
    /// authorization code. A state mismatch creates no connection and a
    /// reused callback cannot succeed.
    pub fn complete(
        &self,
        pending_id: &str,
        callback_url: &str,
        now_unix: u64,
    ) -> Result<(PendingAuthorization, callback::CallbackParams), CoreError> {
        let mut entries = self.entries.lock().unwrap();
        let pending = entries.remove(pending_id).ok_or(CoreError::InvalidInput(
            "unknown or already used authorization",
        ))?;
        if now_unix.saturating_sub(pending.created_unix) > PENDING_TTL.as_secs() {
            return Err(CoreError::InvalidInput("authorization request expired"));
        }
        let params = callback::parse_callback(callback_url, &pending.redirect_uri, &pending.state)?;
        Ok((pending, params))
    }

    /// Complete by the state URL parameter, validating the real callback URL
    /// against the pending's own redirect and state (used when the caller
    /// tracks the pending on its own session, e.g. a desktop shell).
    pub fn complete_by_state(
        &self,
        state_param: &str,
        callback_url: &str,
        now_unix: u64,
    ) -> Result<(PendingAuthorization, callback::CallbackParams), CoreError> {
        let mut entries = self.entries.lock().unwrap();
        let pending_id = entries
            .values()
            .find(|p| p.state == state_param)
            .map(|p| p.id.clone())
            .ok_or(CoreError::InvalidInput(
                "unknown or already used authorization",
            ))?;
        let pending = entries.remove(&pending_id).ok_or(CoreError::InvalidInput(
            "unknown or already used authorization",
        ))?;
        if now_unix.saturating_sub(pending.created_unix) > PENDING_TTL.as_secs() {
            return Err(CoreError::InvalidInput("authorization request expired"));
        }
        let params = callback::parse_callback(callback_url, &pending.redirect_uri, &pending.state)?;
        Ok((pending, params))
    }

    /// Drop every pending request (on cancel, lock or timeout sweep).
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Exchange an authorization code for tokens via the transport (testable
/// against recorded responses). Errors are redacted: never include provider
/// response bodies.
pub async fn exchange_code(
    transport: &dyn HttpTransport,
    pending: &PendingAuthorization,
    code: &str,
) -> Result<TokenResponse, CoreError> {
    let body = form_urlencoded(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &pending.redirect_uri),
        ("client_id", &pending.config.client_id),
        ("code_verifier", pending.code_verifier.expose_secret()),
    ]);
    let resp = transport
        .execute(HttpRequest {
            method: "POST",
            url: pending.config.token_url.clone(),
            headers: vec![(
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: body.into_bytes(),
        })
        .await
        .map_err(|e| match e {
            SyncHttpError::Offline => CoreError::StorageFailure,
            SyncHttpError::Other(_) => CoreError::Internal("token exchange failed"),
        })?;
    parse_token_response(&resp.body)
}

pub async fn refresh_token(
    transport: &dyn HttpTransport,
    config: &OAuthConfig,
    refresh_token: &SecretString,
) -> Result<TokenResponse, CoreError> {
    let body = form_urlencoded(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.expose_secret()),
        ("client_id", &config.client_id),
    ]);
    let resp = transport
        .execute(HttpRequest {
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
            SyncHttpError::Offline => CoreError::StorageFailure,
            SyncHttpError::Other(_) => CoreError::Internal("token refresh failed"),
        })?;
    parse_token_response(&resp.body)
}

pub fn parse_token_response(body: &[u8]) -> Result<TokenResponse, CoreError> {
    let parsed: TokenResponse = serde_json::from_slice(body)
        .map_err(|_| CoreError::Internal("malformed token response"))?;
    if let Some(err) = parsed.error {
        let _ = err;
        // Redacted: invalid_grant etc. must not leak response details.
        return Err(CoreError::InvalidInput(
            "provider rejected the request; reconnect required",
        ));
    }
    if parsed.access_token.is_empty() {
        return Err(CoreError::Internal("malformed token response"));
    }
    Ok(parsed)
}

/// A connected provider account. Token strings are native secrets; UIs get
/// account confirmation and status only.
pub struct ProviderConnection {
    pub id: String,
    pub provider: ProviderKind,
    pub account_email: Option<String>,
    pub access_token: SecretString,
    pub refresh_token: Option<SecretString>,
    pub expires_at_unix: Option<u64>,
}

impl std::fmt::Debug for ProviderConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProviderConnection({:?}, {})",
            self.provider,
            self.account_email.as_deref().unwrap_or("<unknown>")
        )
    }
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn form_urlencoded(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// HTTP Basic auth for WebDAV credentials.
pub fn basic_auth(username: &str, password: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password))
}
