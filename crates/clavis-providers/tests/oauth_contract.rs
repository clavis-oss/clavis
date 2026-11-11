//! OAuth lifecycle contract: state validation, single-use pendings,
//! expiry, redacted errors.

use secrecy::SecretString;

use clavis_core::error::CoreError;
use clavis_providers::oauth::{
    callback::parse_callback, exchange_code, google_config, parse_token_response, PendingStore,
    ReqwestTransport,
};
use clavis_providers::oauth::{HttpRequest, HttpResponse, HttpTransport, SyncHttpError};
use std::sync::Mutex;

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

struct ScriptedTransport {
    responses: Mutex<Vec<HttpResponse>>,
}

#[async_trait::async_trait]
impl HttpTransport for ScriptedTransport {
    async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, SyncHttpError> {
        let mut q = self.responses.lock().unwrap();
        if q.is_empty() {
            return Err(SyncHttpError::Other("no scripted response"));
        }
        Ok(q.remove(0))
    }
}

#[test]
fn begin_creates_single_use_pending_with_state_and_pkce() {
    let store = PendingStore::new();
    let config = google_config("test-client-id", 5175);
    let (id, url) = store.begin(config, 1_000);
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("state="));
    assert!(url.contains("client_id=test-client-id"));
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5175%2Fcallback"));
    let _ = id;
}

#[test]
fn state_mismatch_creates_no_connection() {
    let store = PendingStore::new();
    let config = google_config("test-client-id", 5175);
    let (id, _url) = store.begin(config, 1_000);
    let err = store
        .complete(
            &id,
            "http://127.0.0.1:5175/callback?state=WRONG&code=abc",
            1_100,
        )
        .unwrap_err();
    assert_eq!(err, CoreError::InvalidInput("state mismatch"));
    // Fail closed: the consumed pending means the mismatched attempt cannot
    // be replayed either.
    assert!(store
        .complete(
            &id,
            "http://127.0.0.1:5175/callback?state=WRONG&code=abc",
            1_200
        )
        .is_err());
}

#[test]
fn reused_callback_cannot_succeed() {
    let store = PendingStore::new();
    let config = google_config("test-client-id", 5175);
    let (id, url) = store.begin(config, 1_000);
    // Extract the state from the URL to build a valid callback.
    let state = url
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap()
        .to_string();
    let callback = format!("http://127.0.0.1:5175/callback?state={state}&code=xyz");
    store.complete(&id, &callback, 1_100).unwrap();
    // Second use of the same callback: rejected, no connection.
    let err = store.complete(&id, &callback, 1_200).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn expired_request_is_rejected() {
    let store = PendingStore::new();
    let config = google_config("test-client-id", 5175);
    let (id, url) = store.begin(config, 1_000);
    let state = url
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap()
        .to_string();
    let callback = format!("http://127.0.0.1:5175/callback?state={state}&code=xyz");
    // Six minutes later: past the five-minute TTL.
    let err = store.complete(&id, &callback, 1_000 + 360).unwrap_err();
    assert_eq!(
        err,
        CoreError::InvalidInput("authorization request expired")
    );
}

#[test]
fn provider_error_is_canceled_consent() {
    let err = parse_callback(
        "http://127.0.0.1:5175/callback?state=s&error=access_denied",
        "http://127.0.0.1:5175/callback",
        "s",
    )
    .unwrap_err();
    assert_eq!(err, CoreError::Canceled);
}

#[test]
fn wrong_redirect_rejected() {
    assert!(parse_callback(
        "http://evil.example.com/callback?state=s&code=c",
        "http://127.0.0.1:5175/callback",
        "s",
    )
    .is_err());
    assert!(parse_callback(
        "http://127.0.0.1:9999/callback?state=s&code=c",
        "http://127.0.0.1:5175/callback",
        "s",
    )
    .is_err());
    assert!(parse_callback(
        "http://127.0.0.1:5175/other?state=s&code=c",
        "http://127.0.0.1:5175/callback",
        "s",
    )
    .is_err());
}

#[tokio::test]
async fn invalid_grant_is_redacted() {
    let transport = ScriptedTransport {
        responses: Mutex::new(vec![HttpResponse {
            status: 400,
            body: br#"{"error":"invalid_grant","error_description":"secret internal detail http://token-endpoint-internal"}"#.to_vec(),
            retry_after_secs: None,
        }]),
    };
    let store = PendingStore::new();
    let config = google_config("test-client-id", 5175);
    let (id, url) = store.begin(config, 1_000);
    let state = url
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap()
        .to_string();
    let (pending, _) = store
        .complete(
            &id,
            &format!("http://127.0.0.1:5175/callback?state={state}&code=abc"),
            1_100,
        )
        .unwrap();
    let err = exchange_code(&transport, &pending, "abc")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        !msg.contains("secret internal detail"),
        "provider response must not leak: {msg}"
    );
    assert!(!msg.contains("token-endpoint-internal"));
}

#[tokio::test]
async fn refresh_token_replacement_roundtrip() {
    let transport = ScriptedTransport {
        responses: Mutex::new(vec![HttpResponse {
            status: 200,
            body: br#"{"access_token":"at2","refresh_token":"rt2","expires_in":3600}"#.to_vec(),
            retry_after_secs: None,
        }]),
    };
    let resp = clavis_providers::oauth::refresh_token(
        &transport,
        &google_config("test-client-id", 5175),
        &pass("old-refresh-token"),
    )
    .await
    .unwrap();
    assert_eq!(resp.access_token, "at2");
    assert_eq!(resp.refresh_token.as_deref(), Some("rt2"));
}

#[test]
fn malformed_token_response_rejected() {
    assert!(parse_token_response(br#"{"error":"server_error"}"#).is_err());
    assert!(parse_token_response(br#"not json"#).is_err());
    assert!(parse_token_response(br#"{"access_token":""}"#).is_err());
}

#[test]
fn real_transport_builds() {
    // The production transport exists and is usable behind the http feature.
    let _ = ReqwestTransport::new().unwrap();
}
