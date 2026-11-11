//! Cryptographic primitives for the `clavis-v1` container family.
//!
//! Composition (see docs/security/vault-format-v1.md):
//! - Argon2id v1.3 (64 MiB, 3 passes, 4 lanes) derives a passphrase pre-key.
//! - HKDF-SHA-256 with the vault ID as salt separates domains:
//!   `clavis-v1/passphrase-wrap`, `clavis-v1/recovery-wrap`,
//!   `clavis-v1/payload`, `clavis-v1/export-payload`.
//! - XChaCha20-Poly1305 with independent random 24-byte nonces wraps the root
//!   key and encrypts payloads.
//! - Key-slot AAD is RFC 8785 canonical JSON binding format, vault ID, slot
//!   kind and that slot's public KDF parameters. Payload AAD is the exact
//!   stored header bytes (magic + version + length + header JSON).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canonical::{base64_url_decode, base64_url_unpadded, CanonicalValue};
use crate::error::CoreError;

pub const ROOT_KEY_LEN: usize = 32;
pub const RECOVERY_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

pub const DOMAIN_PASSPHRASE_WRAP: &str = "clavis-v1/passphrase-wrap";
pub const DOMAIN_RECOVERY_WRAP: &str = "clavis-v1/recovery-wrap";
pub const DOMAIN_PAYLOAD: &str = "clavis-v1/payload";
pub const DOMAIN_EXPORT_PAYLOAD: &str = "clavis-v1/export-payload";

/// Random root key from the OS CSPRNG. Never uploaded in plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct RootKey(Zeroizing<[u8; ROOT_KEY_LEN]>);

impl RootKey {
    pub fn generate() -> Self {
        let mut k = [0u8; ROOT_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut k);
        RootKey(Zeroizing::new(k))
    }
    pub fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Self {
        RootKey(Zeroizing::new(bytes))
    }
    pub fn bytes(&self) -> &[u8; ROOT_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RootKey([REDACTED])")
    }
}

/// Persisted KDF parameters. Reader limits: memory <= 256 MiB, passes <= 6,
/// lanes <= 4; anything outside is rejected before computation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    pub salt: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KdfAlgorithm {
    Argon2id,
}

/// Creation parameters for format v1. Benchmarked before format freeze per
/// the plan; a change must update the spec and fixtures together.
pub const CREATION_MEMORY_KIB: u32 = 65536;
pub const CREATION_PASSES: u32 = 3;
pub const CREATION_LANES: u32 = 4;

pub const MAX_MEMORY_KIB: u32 = 262_144;
pub const MAX_PASSES: u32 = 6;
pub const MAX_LANES: u32 = 4;

impl KdfParams {
    pub fn generate() -> Result<Self, CoreError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Ok(KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: CREATION_MEMORY_KIB,
            passes: CREATION_PASSES,
            lanes: CREATION_LANES,
            salt: base64_url_unpadded(&salt),
        })
    }

    pub fn salt_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let s = base64_url_decode(&self.salt).map_err(|_| CoreError::InvalidCredentialOrData)?;
        if s.len() < 8 {
            return Err(CoreError::InvalidCredentialOrData);
        }
        Ok(s)
    }

    /// Validate untrusted reader parameters before doing any KDF work.
    pub fn validate(&self) -> Result<(), CoreError> {
        if !matches!(self.algorithm, KdfAlgorithm::Argon2id) {
            return Err(CoreError::UnsupportedFormat);
        }
        if self.memory_kib == 0 || self.memory_kib > MAX_MEMORY_KIB {
            return Err(CoreError::ResourceLimit);
        }
        if self.passes == 0 || self.passes > MAX_PASSES {
            return Err(CoreError::ResourceLimit);
        }
        if self.lanes == 0 || self.lanes > MAX_LANES {
            return Err(CoreError::ResourceLimit);
        }
        self.salt_bytes()?;
        Ok(())
    }

    fn canonical(&self) -> CanonicalValue {
        CanonicalValue::object(vec![
            ("algorithm", CanonicalValue::Str("argon2id".to_string())),
            ("lanes", CanonicalValue::Int(i64::from(self.lanes))),
            (
                "memory_kib",
                CanonicalValue::Int(i64::from(self.memory_kib)),
            ),
            ("passes", CanonicalValue::Int(i64::from(self.passes))),
            ("salt", CanonicalValue::Str(self.salt.clone())),
        ])
    }
}

/// Enforce the passphrase input limit (<= 1 KiB UTF-8, exact bytes, no
/// trimming or normalization).
pub fn check_passphrase_input(passphrase: &SecretString) -> Result<(), CoreError> {
    if passphrase.expose_secret().len() > 1024 {
        return Err(CoreError::ResourceLimit);
    }
    Ok(())
}

fn argon2id_pre_key(
    passphrase: &SecretString,
    kdf: &KdfParams,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let salt = kdf.salt_bytes()?;
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(32))
        .map_err(|_| CoreError::ResourceLimit)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; 32];
    a2.hash_password_into(passphrase.expose_secret().as_bytes(), &salt, &mut out)
        .map_err(|_| CoreError::Internal("kdf failure"))?;
    Ok(Zeroizing::new(out))
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .expect("32-byte OKM is valid for HKDF-SHA-256");
    okm
}

/// Derive the passphrase wrapping key for a vault namespace.
pub fn derive_passphrase_wrap_key(
    passphrase: &SecretString,
    kdf: &KdfParams,
    vault_id: &crate::ids::VaultId,
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let pre = argon2id_pre_key(passphrase, kdf)?;
    Ok(hkdf_expand(
        &vault_id.as_bytes(),
        &pre,
        DOMAIN_PASSPHRASE_WRAP.as_bytes(),
    ))
}

/// Derive the recovery wrapping key. No KDF slowdown: the recovery key is
/// already 32 random bytes.
pub fn derive_recovery_wrap_key(
    recovery_bytes: &[u8],
    vault_id: &crate::ids::VaultId,
) -> Zeroizing<[u8; 32]> {
    hkdf_expand(
        &vault_id.as_bytes(),
        recovery_bytes,
        DOMAIN_RECOVERY_WRAP.as_bytes(),
    )
}

/// Derive the payload encryption key from the root key.
pub fn derive_payload_key(
    root_key: &RootKey,
    vault_id: &crate::ids::VaultId,
) -> Zeroizing<[u8; 32]> {
    hkdf_expand(
        &vault_id.as_bytes(),
        root_key.bytes(),
        DOMAIN_PAYLOAD.as_bytes(),
    )
}

/// Derive the export container payload key from the root key.
pub fn derive_export_payload_key(
    root_key: &RootKey,
    vault_id: &crate::ids::VaultId,
) -> Zeroizing<[u8; 32]> {
    hkdf_expand(
        &vault_id.as_bytes(),
        root_key.bytes(),
        DOMAIN_EXPORT_PAYLOAD.as_bytes(),
    )
}

/// Canonical key-slot AAD for the given slot kind and public parameters.
pub fn slot_aad(
    domain: &str,
    kind: &str,
    vault_id: &crate::ids::VaultId,
    format: u16,
    kdf: &KdfParams,
) -> Vec<u8> {
    CanonicalValue::object(vec![
        ("domain", CanonicalValue::Str(domain.to_string())),
        ("format", CanonicalValue::Int(i64::from(format))),
        ("kind", CanonicalValue::Str(kind.to_string())),
        ("vault_id", CanonicalValue::Str(vault_id.to_string())),
        ("kdf", kdf.canonical()),
    ])
    .serialize()
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

pub fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail with valid key/nonce")
}

pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::InvalidCredentialOrData)
}

/// Recovery key canonical encoding: `clavis-recovery-v1:` plus unpadded
/// base64url of 32 random bytes. Never reduced to a short PIN.
pub fn encode_recovery_key(bytes: &[u8; RECOVERY_KEY_LEN]) -> String {
    format!("clavis-recovery-v1:{}", base64_url_unpadded(bytes))
}

pub fn decode_recovery_key(encoded: &str) -> Result<[u8; RECOVERY_KEY_LEN], CoreError> {
    let rest = encoded
        .strip_prefix("clavis-recovery-v1:")
        .ok_or(CoreError::InvalidCredentialOrData)?;
    let bytes = base64_url_decode(rest)?;
    let arr: [u8; RECOVERY_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| CoreError::InvalidCredentialOrData)?;
    Ok(arr)
}
