//! `otpauth://` URI parsing. Accepts `otpauth://totp` only. Issuer
//! precedence: the query issuer wins only when the label issuer agrees or is
//! absent; a disagreement requires user correction. Duplicate recognized
//! query parameters are rejected. Unknown parameters are rejected with a
//! typed error so hostile or incompatible content never silently imports.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::import::{base32_decode_secret, MAX_URI_LEN};
use crate::otp::{OtpAlgorithm, OtpConfigValue};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedOtpauthUri {
    pub issuer: Option<String>,
    pub account_label: String,
    pub config: OtpConfigValue,
}

fn percent_decode(s: &str) -> Result<String, CoreError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 3 > bytes.len() {
                return Err(CoreError::InvalidInput("invalid percent encoding"));
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| CoreError::InvalidInput("invalid percent encoding"))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| CoreError::InvalidInput("invalid percent encoding"))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| CoreError::InvalidInput("invalid UTF-8 in label"))
}

pub fn parse_otpauth_uri(input: &str) -> Result<ParsedOtpauthUri, CoreError> {
    if input.len() > MAX_URI_LEN {
        return Err(CoreError::ResourceLimit);
    }
    let (scheme, rest) = input
        .split_once(':')
        .ok_or(CoreError::InvalidInput("not an otpauth URI"))?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err(CoreError::InvalidInput("unsupported URI scheme"));
    }
    let rest = rest
        .strip_prefix("//")
        .ok_or(CoreError::InvalidInput("unsupported URI scheme"))?;
    let (host, tail) = rest
        .split_once('/')
        .ok_or(CoreError::InvalidInput("missing label"))?;
    if !host.eq_ignore_ascii_case("totp") {
        if host.eq_ignore_ascii_case("hotp") {
            return Err(CoreError::InvalidInput("HOTP is not supported"));
        }
        return Err(CoreError::InvalidInput("unsupported otpauth type"));
    }
    let (label_raw, query_raw) = match tail.split_once('?') {
        Some((l, q)) => (l, Some(q)),
        None => (tail, None),
    };
    let label = percent_decode(label_raw)?;
    let (label_issuer, account_label) = match label.split_once(':') {
        Some((iss, acc)) => (Some(iss.trim().to_string()), acc.trim().to_string()),
        None => (None, label.trim().to_string()),
    };
    if account_label.is_empty() {
        return Err(CoreError::InvalidInput("empty account label"));
    }

    // Query parameter parsing with duplicate and unknown detection.
    let mut seen: Vec<(String, String)> = Vec::new();
    if let Some(q) = query_raw {
        for pair in q.split('&') {
            if pair.is_empty() {
                return Err(CoreError::InvalidInput("empty query parameter"));
            }
            let (k, v) = pair
                .split_once('=')
                .ok_or(CoreError::InvalidInput("query parameter without value"))?;
            let key = percent_decode(k)?;
            if !matches!(
                key.as_str(),
                "secret" | "issuer" | "algorithm" | "digits" | "period"
            ) {
                return Err(CoreError::InvalidInput("unsupported URI parameter"));
            }
            if seen.iter().any(|(ek, _)| ek == &key) {
                return Err(CoreError::InvalidInput("duplicate URI parameter"));
            }
            seen.push((key, percent_decode(v)?));
        }
    }

    let get =
        |name: &str| -> Option<&String> { seen.iter().find(|(k, _)| k == name).map(|(_, v)| v) };

    // Issuer precedence: query issuer wins only when the label issuer agrees
    // or is absent.
    let issuer = match (get("issuer"), &label_issuer) {
        (Some(q_iss), None) => Some(q_iss.clone()),
        (Some(q_iss), Some(l_iss)) => {
            if q_iss == l_iss {
                Some(q_iss.clone())
            } else {
                return Err(CoreError::InvalidInput(
                    "issuer disagreement between label and query; correct the entry manually",
                ));
            }
        }
        (None, l) => l.clone(),
    };

    let secret =
        base32_decode_secret(get("secret").ok_or(CoreError::InvalidInput("missing secret"))?)?;
    let algorithm = match get("algorithm").map(|s| s.as_str()) {
        None => OtpAlgorithm::Sha1,
        Some(a) if a.eq_ignore_ascii_case("SHA1") => OtpAlgorithm::Sha1,
        Some(a) if a.eq_ignore_ascii_case("SHA256") => OtpAlgorithm::Sha256,
        Some(a) if a.eq_ignore_ascii_case("SHA512") => OtpAlgorithm::Sha512,
        Some(_) => return Err(CoreError::InvalidInput("unsupported algorithm")),
    };
    let digits = match get("digits").map(|s| s.as_str()) {
        None => 6,
        Some(d) => {
            let n: u8 = d
                .parse()
                .map_err(|_| CoreError::InvalidInput("invalid digits value"))?;
            n
        }
    };
    let period = match get("period").map(|s| s.as_str()) {
        None => 30,
        Some(p) => p
            .parse::<u32>()
            .map_err(|_| CoreError::InvalidInput("invalid period value"))?,
    };
    let config = OtpConfigValue {
        secret,
        algorithm,
        digits,
        period_seconds: period,
    };
    config.validate()?;
    Ok(ParsedOtpauthUri {
        issuer,
        account_label,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_google_style_uri() {
        let u = parse_otpauth_uri(
            "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(u.issuer.as_deref(), Some("Example"));
        assert_eq!(u.account_label, "alice@example.com");
        assert_eq!(u.config.algorithm, OtpAlgorithm::Sha1);
        assert_eq!(u.config.digits, 6);
        assert_eq!(u.config.period_seconds, 30);
    }

    #[test]
    fn rejects_hotp_and_unknown_params() {
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(
            parse_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&image=http%3A%2F%2Fx")
                .is_err()
        );
        assert!(parse_otpauth_uri("https://example.com/x").is_err());
    }

    #[test]
    fn rejects_duplicate_parameters() {
        assert!(parse_otpauth_uri(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP"
        )
        .is_err());
    }

    #[test]
    fn rejects_issuer_disagreement() {
        assert!(parse_otpauth_uri(
            "otpauth://totp/Other%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        )
        .is_err());
    }
}
