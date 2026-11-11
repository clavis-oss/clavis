//! TOTP (RFC 6238). SHA-1/256/512, 6 or 8 digits, periods 15–120 seconds.
//! Seeds never serialize as raw bytes through any transport.

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::canonical::base64_url_unpadded;
use crate::error::CoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Secret seed bytes. Best-effort zeroized on drop; never Debug/Display.
#[derive(Clone, PartialEq, Eq)]
pub struct OtpSeed(Zeroizing<Vec<u8>>);

impl OtpSeed {
    pub fn new(bytes: Vec<u8>) -> Self {
        OtpSeed(Zeroizing::new(bytes))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for OtpSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OtpSeed([REDACTED {} bytes])", self.0.len())
    }
}

impl serde::Serialize for OtpSeed {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64_url_unpadded(self.bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for OtpSeed {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = crate::canonical::base64_url_decode(&s).map_err(serde::de::Error::custom)?;
        Ok(OtpSeed::new(bytes))
    }
}

/// Serialized OTP configuration used inside causal snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpConfigValue {
    pub secret: OtpSeed,
    pub algorithm: OtpAlgorithm,
    pub digits: u8,
    pub period_seconds: u32,
}

impl OtpConfigValue {
    /// Reject unsupported parameters before anything is stored.
    pub fn validate(&self) -> Result<(), CoreError> {
        if !(6..=128).contains(&self.secret.len()) {
            return Err(CoreError::InvalidInput("seed must decode to 10-128 bytes"));
        }
        if !matches!(self.digits, 6 | 8) {
            return Err(CoreError::InvalidInput("digits must be 6 or 8"));
        }
        if !(15..=120).contains(&self.period_seconds) {
            return Err(CoreError::InvalidInput("period must be 15-120 seconds"));
        }
        Ok(())
    }
}

/// OTP configuration as used by the generator (same data, borrowable).
#[derive(Clone, Debug)]
pub struct OtpConfig {
    pub seed: OtpSeed,
    pub algorithm: OtpAlgorithm,
    pub digits: u8,
    pub period_seconds: u32,
}

impl From<&OtpConfigValue> for OtpConfig {
    fn from(v: &OtpConfigValue) -> Self {
        OtpConfig {
            seed: v.secret.clone(),
            algorithm: v.algorithm,
            digits: v.digits,
            period_seconds: v.period_seconds,
        }
    }
}

/// A generated code plus the exact instant it stops being valid. Wire times
/// crossing JavaScript are decimal strings at the bridge boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpCode {
    pub value: String,
    pub valid_until_unix_ms: u64,
}

fn hmac_bytes(algorithm: OtpAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn dynamic_truncate(hmac: &[u8]) -> u32 {
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
    let bin = &hmac[offset..offset + 4];
    u32::from_be_bytes([bin[0], bin[1], bin[2], bin[3]]) & 0x7fff_ffff
}

/// Generate the TOTP code valid at `unix_seconds` for the given config.
pub fn totp_at(config: &OtpConfig, unix_seconds: u64) -> Result<OtpCode, CoreError> {
    if !matches!(config.digits, 6 | 8) {
        return Err(CoreError::InvalidInput("digits must be 6 or 8"));
    }
    if config.period_seconds == 0 {
        return Err(CoreError::InvalidInput("period must not be zero"));
    }
    let counter = unix_seconds / u64::from(config.period_seconds);
    let msg = counter.to_be_bytes();
    let mac = hmac_bytes(config.algorithm, config.seed.bytes(), &msg);
    let code_num = dynamic_truncate(&mac) % 10u32.pow(u32::from(config.digits));
    let value = format!("{:0width$}", code_num, width = config.digits as usize);
    let valid_until = (counter + 1) * u64::from(config.period_seconds);
    Ok(OtpCode {
        value,
        valid_until_unix_ms: valid_until.saturating_mul(1000),
    })
}
