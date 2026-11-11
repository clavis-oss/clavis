//! Encrypted provider credentials. Access/refresh tokens and the provider
//! account email are encrypted with a device-specific key in the
//! `clavis-v1/device-credentials:<device_id>` domain. A supplied recovery
//! key is never retained here. Tokens stay out of the cloud vault, React
//! stores, URLs, logs and exported backups.

use rand::RngCore;
use zeroize::Zeroizing;

use clavis_core::error::CoreError;
use clavis_core::vault::crypto::{aead_open, aead_seal, random_nonce};

use crate::db::{read_private_file, write_private_file, Store};

/// 32 random bytes generated per store, stored in a 0600 file next to the
/// database. Without an OS keyring (tiling/headless Linux), the threat model
/// treats a compromised local user account as out of scope for v1; this key
/// only prevents casual plaintext discovery.
pub struct DeviceKey {
    bytes: Zeroizing<[u8; 32]>,
    device_id: String,
}

const DEVICE_KEY_MAGIC: &[u8; 4] = b"CLK1";

pub fn load_or_create_device_key(db_path: &std::path::Path) -> Result<DeviceKey, CoreError> {
    let key_path = db_path.with_extension("devicekey");
    if let Some(existing) = read_private_file(&key_path)? {
        if existing.len() == 4 + 32 + 36 && &existing[..4] == DEVICE_KEY_MAGIC {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&existing[4..36]);
            let device_id = String::from_utf8(existing[36..].to_vec())
                .map_err(|_| CoreError::StorageFailure)?;
            return Ok(DeviceKey {
                bytes: Zeroizing::new(bytes),
                device_id,
            });
        }
        return Err(CoreError::StorageFailure);
    }
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let device_id = clavis_core::ids::DeviceId::generate().0.to_string();
    let mut blob = Vec::with_capacity(4 + 32 + device_id.len());
    blob.extend_from_slice(DEVICE_KEY_MAGIC);
    blob.extend_from_slice(&bytes);
    blob.extend_from_slice(device_id.as_bytes());
    write_private_file(&key_path, &blob)?;
    Ok(DeviceKey {
        bytes: Zeroizing::new(bytes),
        device_id,
    })
}

impl DeviceKey {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    fn encrypt(&self, vault_id: &clavis_core::ids::VaultId, plaintext: &[u8]) -> Vec<u8> {
        let hk = hkdf_device(vault_id, &self.bytes);
        let nonce = random_nonce();
        let aad = format!("clavis-v1/device-credentials:{}", self.device_id);
        // Nonce is prefixed to the blob so decrypt can recover it.
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&aead_seal(&hk, &nonce, plaintext, aad.as_bytes()));
        blob
    }

    fn decrypt(
        &self,
        vault_id: &clavis_core::ids::VaultId,
        blob: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        if blob.len() < 24 + 16 {
            return Err(CoreError::StorageFailure);
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&blob[..24]);
        let hk = hkdf_device(vault_id, &self.bytes);
        let aad = format!("clavis-v1/device-credentials:{}", self.device_id);
        aead_open(&hk, &nonce, &blob[24..], aad.as_bytes())
    }
}

fn hkdf_device(vault_id: &clavis_core::ids::VaultId, device_key: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&vault_id.as_bytes()), device_key);
    let mut okm = [0u8; 32];
    hk.expand(b"clavis-v1/device-credentials", &mut okm)
        .expect("32-byte OKM");
    okm
}

/// Store for encrypted provider credentials keyed by connection id.
pub struct CredentialStore {
    vault_id: clavis_core::ids::VaultId,
    device_key: DeviceKey,
}

impl CredentialStore {
    pub fn new(vault_id: clavis_core::ids::VaultId, device_key: DeviceKey) -> Self {
        CredentialStore {
            vault_id,
            device_key,
        }
    }

    pub fn put(&self, store: &Store, key: &str, plaintext: &[u8]) -> Result<(), CoreError> {
        let blob = self.device_key.encrypt(&self.vault_id, plaintext);
        store.tx(|conn| {
            conn.execute(
                "INSERT INTO credentials (key, data) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET data = excluded.data",
                rusqlite::params![key, blob],
            )
            .map_err(|_| CoreError::StorageFailure)?;
            Ok(())
        })
    }

    pub fn get(&self, store: &Store, key: &str) -> Result<Option<Vec<u8>>, CoreError> {
        store.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT data FROM credentials WHERE key = ?1")
                .map_err(|_| CoreError::StorageFailure)?;
            let mut rows = stmt.query([key]).map_err(|_| CoreError::StorageFailure)?;
            if let Some(row) = rows.next().map_err(|_| CoreError::StorageFailure)? {
                let blob: Vec<u8> = row.get(0).map_err(|_| CoreError::StorageFailure)?;
                return self.device_key.decrypt(&self.vault_id, &blob).map(Some);
            }
            Ok(None)
        })
    }

    pub fn remove(&self, store: &Store, key: &str) -> Result<(), CoreError> {
        store.tx(|conn| {
            conn.execute("DELETE FROM credentials WHERE key = ?1", [key])
                .map_err(|_| CoreError::StorageFailure)?;
            Ok(())
        })
    }
}
