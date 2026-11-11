//! PKCE S256 helpers and anti-CSRF state tokens.

use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

/// Random URL-safe token of `n` random bytes, base64url unpadded.
pub fn random_token(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64_url(&buf)
}

pub fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// S256 code challenge from a verifier.
pub fn challenge_s256(verifier: &SecretString) -> String {
    let digest = Sha256::digest(verifier.expose_secret().as_bytes());
    base64_url(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn rfc7636_appendix_b_vector() {
        let verifier = SecretString::new(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                .to_string()
                .into(),
        );
        assert_eq!(
            challenge_s256(&verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
