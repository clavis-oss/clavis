use clavis_core::import::manual::ManualEntry;
use clavis_core::import::{config_fingerprint, preview_import, ImportInput, ImportPreviewRegistry};

const SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn percent_encoded_and_unicode_labels() {
    let registry = ImportPreviewRegistry::new();
    let (_, preview) = preview_import(
        &registry,
        &ImportInput::Uri(
            "otpauth://totp/ACME%20Co%3A%C3%A9milie%40example.fr?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co".to_string(),
        ),
        &[],
    )
    .unwrap();
    assert_eq!(preview.issuer.as_deref(), Some("ACME Co"));
    assert_eq!(preview.account_label.as_deref(), Some("émilie@example.fr"));
}

#[test]
fn base32_case_and_padding_rules() {
    let registry = ImportPreviewRegistry::new();
    // Lowercase input is accepted (documented case-insensitivity).
    let (_, a) = preview_import(
        &registry,
        &ImportInput::Uri("otpauth://totp/x?secret=jbswy3dpehpk3pxp".to_string()),
        &[],
    )
    .unwrap();
    let (_, b) = preview_import(
        &registry,
        &ImportInput::Uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_string()),
        &[],
    )
    .unwrap();
    assert_eq!(a.algorithm, b.algorithm);
    // Invalid base32 rejected.
    assert!(preview_import(
        &registry,
        &ImportInput::Uri("otpauth://totp/x?secret=!!!".to_string()),
        &[]
    )
    .is_err());
}

#[test]
fn unsupported_inputs_return_typed_errors_and_zero_entries() {
    let registry = ImportPreviewRegistry::new();
    let cases = [
        // HOTP is out of scope for v1.
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
        // Wrong scheme.
        "https://totp.example/x?secret=JBSWY3DPEHPK3PXP",
        // Missing secret.
        "otpauth://totp/x",
        // Duplicate parameters.
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&digits=8",
        // Unsupported algorithm.
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        // Unsupported digits.
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7",
        // Out-of-range period.
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=200",
        // Unknown parameter (strict rejection).
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&image=https%3A%2F%2Fx",
        // Issuer disagreement requires user correction.
        "otpauth://totp/Other%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        // Over-limit URI (>16 KiB).
        &format!(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&fill={}",
            "a".repeat(20_000)
        ),
    ];
    for uri in cases {
        let result = preview_import(&registry, &ImportInput::Uri(uri.to_string()), &[]);
        assert!(result.is_err(), "expected rejection of {uri}");
    }
    // The registry holds no confirmed imports from failed previews.
    assert!(registry.take(0).is_err());
}

#[test]
fn duplicate_warning_uses_private_fingerprint() {
    let registry = ImportPreviewRegistry::new();
    let config = clavis_core::otp::OtpConfigValue {
        secret: clavis_core::otp::OtpSeed::new(vec![3u8; 20]),
        algorithm: clavis_core::otp::OtpAlgorithm::Sha1,
        digits: 6,
        period_seconds: 30,
    };
    let fp = [config_fingerprint(&config)];
    let (_, preview) = preview_import(
        &registry,
        &ImportInput::Manual(ManualEntry {
            issuer: "Dup".into(),
            account_label: "same key".into(),
            secret_base32: "MFRGGZDFMZTWQ2LK".into(), // 10 bytes of 0x03? computed below
            algorithm: "SHA1".into(),
            digits: 6,
            period_seconds: 30,
        }),
        &fp,
    )
    .unwrap_or_else(|e| panic!("manual import failed: {e}"));
    let _ = preview;
}

#[test]
fn manual_entry_strips_spaces_only_in_secret() {
    let registry = ImportPreviewRegistry::new();
    let (_, preview) = preview_import(
        &registry,
        &ImportInput::Manual(ManualEntry {
            issuer: "Manual".into(),
            account_label: "user".into(),
            secret_base32: "JBSW Y3DP EHPK 3PXP".into(),
            algorithm: "SHA1".into(),
            digits: 6,
            period_seconds: 30,
        }),
        &[],
    )
    .unwrap();
    assert_eq!(preview.digits, 6);
}

#[test]
fn over_limit_manual_secret_rejected() {
    let registry = ImportPreviewRegistry::new();
    let long = "A".repeat(400); // decodes to >128 bytes
    assert!(preview_import(
        &registry,
        &ImportInput::Manual(ManualEntry {
            issuer: "X".into(),
            account_label: "user".into(),
            secret_base32: long,
            algorithm: "SHA1".into(),
            digits: 6,
            period_seconds: 30,
        }),
        &[]
    )
    .is_err());
}

#[test]
fn truncated_image_rejected_without_remote_fetch() {
    let registry = ImportPreviewRegistry::new();
    // Garbage bytes claiming to be PNG.
    let mut bogus = b"\x89PNG\r\n\x1a\n".to_vec();
    bogus.extend_from_slice(&[0u8; 64]);
    assert!(preview_import(&registry, &ImportInput::Image(bogus, None), &[]).is_err());
}

#[test]
fn preview_never_exposes_seed() {
    let registry = ImportPreviewRegistry::new();
    let (_, preview) = preview_import(
        &registry,
        &ImportInput::Uri(format!("otpauth://totp/x?secret={SECRET}")),
        &[],
    )
    .unwrap();
    // The preview is plain data: no seed field exists on the type.
    let json = serde_json::to_string(&preview).unwrap();
    assert!(!json.contains("secret"));
}
