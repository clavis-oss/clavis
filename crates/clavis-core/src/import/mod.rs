pub mod manual;
pub mod qr;
pub mod uri;

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::otp::{OtpAlgorithm, OtpConfigValue, OtpSeed};

pub const MAX_URI_LEN: usize = 16 * 1024;
pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_IMAGE_PIXELS: usize = 16_000_000;

/// User-facing import input. QR/URI content is attacker-controlled data:
/// it is parsed as text, never opened, fetched or rendered.
#[derive(Clone)]
pub enum ImportInput {
    Uri(String),
    /// Encoded image bytes (PNG/JPEG) with the QR candidate index chosen by
    /// the user when the image contains multiple codes.
    Image(Vec<u8>, Option<usize>),
    Manual(manual::ManualEntry),
}

/// Safe preview exposed to UIs: parameters only, never the decoded seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportPreview {
    pub issuer: Option<String>,
    pub account_label: Option<String>,
    pub algorithm: OtpAlgorithm,
    pub digits: u8,
    pub period_seconds: u32,
    pub duplicate_warning: bool,
}

/// Full parsed import kept behind an opaque preview handle.
#[derive(Clone, Debug)]
pub struct ParsedImport {
    pub issuer: Option<String>,
    pub account_label: Option<String>,
    pub config: OtpConfigValue,
}

impl std::fmt::Debug for ImportPreviewRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ImportPreviewRegistry")
    }
}

#[derive(Default)]
pub struct ImportPreviewRegistry {
    next_id: Mutex<u64>,
    entries: Mutex<BTreeMap<u64, ParsedImport>>,
}

impl ImportPreviewRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, parsed: ParsedImport) -> u64 {
        let mut next = self.next_id.lock().expect("registry");
        let id = *next;
        *next += 1;
        self.entries.lock().expect("registry").insert(id, parsed);
        id
    }

    /// Taking a handle consumes it; handles expire on cancel or lock.
    pub fn take(&self, handle: u64) -> Result<ParsedImport, CoreError> {
        self.entries
            .lock()
            .expect("registry")
            .remove(&handle)
            .ok_or(CoreError::InvalidInput("unknown or expired import preview"))
    }

    pub fn clear(&self) {
        self.entries.lock().expect("registry").clear();
    }
}

/// Fingerprint of an OTP configuration for the private duplicate warning.
/// Computed locally inside the encrypted domain; never published anywhere.
pub fn config_fingerprint(config: &OtpConfigValue) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"clavis-v1/duplicate-fingerprint");
    hasher.update(config.secret.bytes());
    hasher.update([match config.algorithm {
        OtpAlgorithm::Sha1 => 1,
        OtpAlgorithm::Sha256 => 2,
        OtpAlgorithm::Sha512 => 3,
    }]);
    hasher.update([config.digits]);
    hasher.update(config.period_seconds.to_be_bytes());
    hasher.finalize().into()
}

/// Parse any import input into a preview plus an opaque handle.
pub fn preview_import(
    registry: &ImportPreviewRegistry,
    input: &ImportInput,
    existing_fingerprints: &[[u8; 32]],
) -> Result<(u64, ImportPreview), CoreError> {
    let parsed = match input {
        ImportInput::Uri(text) => {
            let u = uri::parse_otpauth_uri(text)?;
            ParsedImport {
                issuer: u.issuer.clone(),
                account_label: Some(u.account_label),
                config: u.config,
            }
        }
        ImportInput::Image(bytes, selection) => {
            let text = qr::decode_qr_from_image(bytes, *selection)?;
            let u = uri::parse_otpauth_uri(&text)?;
            ParsedImport {
                issuer: u.issuer.clone(),
                account_label: Some(u.account_label),
                config: u.config,
            }
        }
        ImportInput::Manual(entry) => {
            let m = manual::parse_manual_entry(entry)?;
            ParsedImport {
                issuer: (!entry.issuer.is_empty()).then(|| entry.issuer.clone()),
                account_label: Some(entry.account_label.clone()),
                config: m,
            }
        }
    };
    let duplicate_warning = existing_fingerprints.contains(&config_fingerprint(&parsed.config));
    let preview = ImportPreview {
        issuer: parsed.issuer.clone(),
        account_label: parsed.account_label.clone(),
        algorithm: parsed.config.algorithm,
        digits: parsed.config.digits,
        period_seconds: parsed.config.period_seconds,
        duplicate_warning,
    };
    let handle = registry.insert(parsed);
    Ok((handle, preview))
}

/// RFC 4648 Base32 decoding with documented case-insensitive input.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, CoreError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32,
            b'2'..=b'7' => (c - b'2' + 26) as u32,
            b'=' => continue,
            _ => return Err(CoreError::InvalidInput("invalid base32 character")),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push(((acc >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

pub fn base32_decode_secret(input: &str) -> Result<OtpSeed, CoreError> {
    let bytes = base32_decode(input)?;
    if !(10..=128).contains(&bytes.len()) {
        return Err(CoreError::InvalidInput(
            "secret must decode to 10-128 bytes",
        ));
    }
    Ok(OtpSeed::new(bytes))
}
