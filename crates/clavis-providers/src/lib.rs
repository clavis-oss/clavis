//! Storage provider integrations. Adapters implement the common
//! `RemoteStore` transport contract; provider-specific types never enter
//! OTP account data or the portable encrypted format.

pub mod dropbox;
pub mod google;
pub mod oauth;
pub mod onedrive;
pub mod webdav;

/// Which storage provider backs a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    GoogleDrive,
    OneDrive,
    Dropbox,
    WebDav,
}

impl ProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderKind::GoogleDrive => "google_drive",
            ProviderKind::OneDrive => "onedrive",
            ProviderKind::Dropbox => "dropbox",
            ProviderKind::WebDav => "webdav",
        }
    }

    pub fn parse(s: &str) -> Option<ProviderKind> {
        match s {
            "google_drive" => Some(ProviderKind::GoogleDrive),
            "onedrive" => Some(ProviderKind::OneDrive),
            "dropbox" => Some(ProviderKind::Dropbox),
            "webdav" => Some(ProviderKind::WebDav),
            _ => None,
        }
    }
}
