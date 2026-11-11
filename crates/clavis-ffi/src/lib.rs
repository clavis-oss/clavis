//! UniFFI bridge contract for the React Native clients. The surface is
//! deliberately narrow: no root key, seed or OAuth token is exposed to JS,
//! and there is no arbitrary filesystem API. u64 timestamps cross the bridge
//! as decimal strings; session identifiers are opaque strings.

/// Build contract for phase 1 spikes: every client and the native bridge
/// must agree on the format version.
#[uniffi::export]
pub fn core_info() -> CoreInfo {
    CoreInfo {
        format_version: clavis_core::FORMAT_VERSION,
    }
}

#[derive(uniffi::Record, Debug)]
pub struct CoreInfo {
    pub format_version: u16,
}

uniffi::setup_scaffolding!("clavis");

#[cfg(test)]
mod tests {
    use crate::core_info;

    #[test]
    fn contract_format_version() {
        assert_eq!(core_info().format_version, 1);
    }
}
