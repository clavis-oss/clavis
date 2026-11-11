//! Connection records for encrypted local persistence. The owning app layer
//! encrypts these bytes with the device credential store before writing
//! them to the local database; they never enter the cloud vault or exports.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::ProviderKind;
use clavis_core::error::CoreError;

#[derive(Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub connection_id: String,
    pub provider: ProviderKind,
    pub account_email: Option<String>,
    pub access_token_b64: String,
    pub refresh_token_b64: Option<String>,
    pub expires_at_unix: Option<u64>,
}

impl ConnectionRecord {
    pub fn access_token(&self) -> SecretString {
        SecretString::new(self.access_token_b64.clone().into())
    }

    pub fn refresh_token(&self) -> Option<SecretString> {
        self.refresh_token_b64
            .as_ref()
            .map(|r| SecretString::new(r.clone().into()))
    }

    pub fn serialize(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_vec(self).map_err(|_| CoreError::Internal("connection serialize"))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, CoreError> {
        serde_json::from_slice(bytes).map_err(|_| CoreError::IntegrityFailure)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_id: String,
        provider: ProviderKind,
        account_email: Option<String>,
        access_token: &SecretString,
        refresh_token: Option<&SecretString>,
        expires_at_unix: Option<u64>,
    ) -> Self {
        ConnectionRecord {
            connection_id,
            provider,
            account_email,
            access_token_b64: access_token.expose_secret().to_string(),
            refresh_token_b64: refresh_token.map(|r| r.expose_secret().to_string()),
            expires_at_unix,
        }
    }
}
