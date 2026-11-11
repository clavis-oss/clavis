use clavis_core::otp::{totp_at, OtpAlgorithm, OtpConfig, OtpSeed};

fn config(alg: OtpAlgorithm, digits: u8, seed: &[u8]) -> OtpConfig {
    OtpConfig {
        seed: OtpSeed::new(seed.to_vec()),
        algorithm: alg,
        digits,
        period_seconds: 30,
    }
}

/// RFC 6238 Appendix B test vectors (8 digits, T0=0, 30-second steps).
#[test]
fn rfc6238_vectors_sha1_256_512() {
    // The RFC vectors use the ASCII seeds "12345678901234567890" (SHA1),
    // "12345678901234567890123456789012" (SHA256), and the 64-byte seed
    // for SHA512.
    let seeds: [(&str, &[u8]); 3] = [
        ("SHA1", b"12345678901234567890"),
        ("SHA256", b"12345678901234567890123456789012"),
        (
            "SHA512",
            b"1234567890123456789012345678901234567890123456789012345678901234",
        ),
    ];
    let cases: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];
    for (t, sha1, sha256, sha512) in cases {
        let got = |alg: OtpAlgorithm, digits: u8, seed: &[u8]| -> String {
            totp_at(&config(alg, digits, seed), t).unwrap().value
        };
        assert_eq!(got(OtpAlgorithm::Sha1, 8, seeds[0].1), sha1, "sha1 at {t}");
        assert_eq!(
            got(OtpAlgorithm::Sha256, 8, seeds[1].1),
            sha256,
            "sha256 at {t}"
        );
        assert_eq!(
            got(OtpAlgorithm::Sha512, 8, seeds[2].1),
            sha512,
            "sha512 at {t}"
        );
    }
}

#[test]
fn sha1_at_59_8_digits() {
    assert_eq!(
        totp_at(&config(OtpAlgorithm::Sha1, 8, b"12345678901234567890"), 59)
            .unwrap()
            .value,
        "94287082"
    );
}

/// The 6-digit code is the same dynamic truncation reduced mod 10^6.
#[test]
fn six_digit_variant_is_consistent() {
    let c = totp_at(&config(OtpAlgorithm::Sha1, 6, b"12345678901234567890"), 59).unwrap();
    assert_eq!(c.value, "287082");
}

#[test]
fn leading_zero_padding() {
    // T=1111111109 -> 07081804: leading zero must be preserved.
    let c = totp_at(
        &config(OtpAlgorithm::Sha1, 8, b"12345678901234567890"),
        1111111109,
    )
    .unwrap();
    assert!(c.value.starts_with('0'));
    assert_eq!(c.value.len(), 8);
}

#[test]
fn validity_window_and_boundaries() {
    let c = totp_at(&config(OtpAlgorithm::Sha1, 6, b"12345678901234567890"), 59).unwrap();
    assert_eq!(c.valid_until_unix_ms, 60_000, "valid until the step ends");
    // One second before rollover is still the same code; at rollover it
    // changes.
    let a = totp_at(&config(OtpAlgorithm::Sha1, 6, b"12345678901234567890"), 59).unwrap();
    let b = totp_at(&config(OtpAlgorithm::Sha1, 6, b"12345678901234567890"), 60).unwrap();
    assert_ne!(a.value, b.value);
}

#[test]
fn alternative_supported_period() {
    let mut c = config(OtpAlgorithm::Sha1, 6, b"12345678901234567890");
    c.period_seconds = 60;
    let at_59 = totp_at(&c, 59).unwrap();
    let at_60 = totp_at(&c, 60).unwrap();
    assert_eq!(at_59.valid_until_unix_ms, 60_000);
    assert_ne!(at_59.value, at_60.value);
}

#[test]
fn future_timestamps_through_2038_and_beyond() {
    // 2038-01-19T03:14:08Z and a far-future timestamp must not overflow.
    let c = config(OtpAlgorithm::Sha1, 8, b"12345678901234567890");
    let r = totp_at(&c, 2_147_483_648);
    assert!(r.is_ok());
    let r = totp_at(&c, 4_000_000_000);
    assert!(r.is_ok());
}

#[test]
fn rejects_unsupported_parameters() {
    let mut c = config(OtpAlgorithm::Sha1, 7, b"12345678901234567890");
    assert!(totp_at(&c, 0).is_err());
    c.digits = 6;
    c.period_seconds = 0;
    assert!(totp_at(&c, 0).is_err());
}
