//! Manual key entry. Spaces are removed from the secret only here — never
//! from arbitrary URI content — and all parameters are validated.

use crate::error::CoreError;
use crate::import::base32_decode_secret;
use crate::otp::{OtpAlgorithm, OtpConfigValue};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManualEntry {
    pub issuer: String,
    pub account_label: String,
    pub secret_base32: String,
    pub algorithm: String,
    pub digits: u8,
    pub period_seconds: u32,
}

pub fn parse_manual_entry(entry: &ManualEntry) -> Result<OtpConfigValue, CoreError> {
    if entry.account_label.trim().is_empty() {
        return Err(CoreError::InvalidInput("account label is required"));
    }
    if entry.account_label.len() > 512 || entry.issuer.len() > 512 {
        return Err(CoreError::ResourceLimit);
    }
    // Manual entry removes spaces from the typed key.
    let cleaned: String = entry.secret_base32.chars().filter(|c| *c != ' ').collect();
    let secret = base32_decode_secret(&cleaned)?;
    let algorithm = match entry.algorithm.as_str() {
        "SHA1" | "sha1" => OtpAlgorithm::Sha1,
        "SHA256" | "sha256" => OtpAlgorithm::Sha256,
        "SHA512" | "sha512" => OtpAlgorithm::Sha512,
        other => {
            let _ = other;
            return Err(CoreError::InvalidInput(
                "unsupported algorithm; use SHA1, SHA256 or SHA512",
            ));
        }
    };
    let config = OtpConfigValue {
        secret,
        algorithm,
        digits: entry.digits,
        period_seconds: entry.period_seconds,
    };
    config.validate()?;
    Ok(config)
}
