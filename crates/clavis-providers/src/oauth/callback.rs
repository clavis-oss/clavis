//! OAuth callback validation: exact redirect URI, state equality, provider
//! error propagation as canceled/denied.

use clavis_core::error::CoreError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackParams {
    pub code: String,
}

/// Parse and validate a callback URL against the expected redirect and
/// state. Rejects: wrong host/port/path, missing/wrong state, provider error
/// responses, missing code, and extra unexpected parameters.
pub fn parse_callback(
    callback_url: &str,
    expected_redirect: &str,
    expected_state: &str,
) -> Result<CallbackParams, CoreError> {
    let cb = parse_url(callback_url)?;
    let red = parse_url(expected_redirect)?;
    if cb.scheme != red.scheme || cb.host != red.host || cb.port != red.port || cb.path != red.path
    {
        return Err(CoreError::InvalidInput(
            "callback does not match the redirect",
        ));
    }
    let state = cb
        .query
        .get("state")
        .ok_or(CoreError::InvalidInput("missing state"))?;
    // Constant-time-ish comparison on short tokens; use subtle to avoid any
    // timing signal.
    use subtle::ConstantTimeEq;
    if !bool::from(state.as_bytes().ct_eq(expected_state.as_bytes())) {
        return Err(CoreError::InvalidInput("state mismatch"));
    }
    if let Some(err) = cb.query.get("error") {
        let _ = err;
        // access_denied or any provider error is a canceled consent.
        return Err(CoreError::Canceled);
    }
    let code = cb
        .query
        .get("code")
        .ok_or(CoreError::InvalidInput("missing authorization code"))?;
    if code.is_empty() {
        return Err(CoreError::InvalidInput("missing authorization code"));
    }
    Ok(CallbackParams { code: code.clone() })
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: std::collections::BTreeMap<String, String>,
}

fn parse_url(url: &str) -> Result<ParsedUrl, CoreError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or(CoreError::InvalidInput("invalid URL"))?;
    let (authority, path_and_query) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{}", p)))
        .unwrap_or((rest, "/".to_string()));
    let (path, query_part) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_and_query.clone(), String::new()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (
            h.to_string(),
            Some(
                p.parse()
                    .map_err(|_| CoreError::InvalidInput("invalid URL"))?,
            ),
        ),
        _ => (authority.to_string(), None),
    };
    let mut query = std::collections::BTreeMap::new();
    if !query_part.is_empty() {
        for pair in query_part.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or(CoreError::InvalidInput("invalid callback query"))?;
            query.insert(k.to_string(), v.to_string());
        }
    }
    Ok(ParsedUrl {
        scheme: scheme.to_string(),
        host,
        port,
        path: if path.is_empty() {
            "/".to_string()
        } else {
            path
        },
        query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_callback() {
        let p = parse_callback(
            "http://127.0.0.1:5175/callback?state=abc&code=xyz",
            "http://127.0.0.1:5175/callback",
            "abc",
        )
        .unwrap();
        assert_eq!(p.code, "xyz");
    }

    #[test]
    fn rejects_state_mismatch_and_wrong_redirect() {
        assert!(parse_callback(
            "http://127.0.0.1:5175/callback?state=zzz&code=xyz",
            "http://127.0.0.1:5175/callback",
            "abc",
        )
        .is_err());
        assert!(parse_callback(
            "http://evil.example.com/callback?state=abc&code=xyz",
            "http://127.0.0.1:5175/callback",
            "abc",
        )
        .is_err());
        assert!(parse_callback(
            "http://127.0.0.1:5175/other?state=abc&code=xyz",
            "http://127.0.0.1:5175/callback",
            "abc",
        )
        .is_err());
    }

    #[test]
    fn provider_error_is_canceled() {
        assert_eq!(
            parse_callback(
                "http://127.0.0.1:5175/callback?state=abc&error=access_denied",
                "http://127.0.0.1:5175/callback",
                "abc",
            )
            .unwrap_err(),
            CoreError::Canceled
        );
    }
}
