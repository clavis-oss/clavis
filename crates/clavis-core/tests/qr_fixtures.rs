use clavis_core::import::preview_import;
use clavis_core::import::ImportInput;
use clavis_core::import::ImportPreviewRegistry;

/// Fixture QR images (see tests/fixtures/qr/) contain synthetic otpauth
/// URIs only. Scanned content is parsed as text; it is never fetched,
/// rendered or opened.
#[test]
fn decodes_qr_image_fixture() {
    let registry = ImportPreviewRegistry::new();
    let bytes = std::fs::read("../../tests/fixtures/qr/otpauth_example.png").unwrap();
    let (handle, preview) = preview_import(&registry, &ImportInput::Image(bytes, None), &[])
        .expect("fixture QR must decode");
    assert_eq!(preview.issuer.as_deref(), Some("Example"));
    assert_eq!(
        preview.account_label.as_deref(),
        Some("synthetic@example.com")
    );
    registry.take(handle).unwrap();
}

#[test]
fn multiple_qr_candidates_require_selection() {
    let registry = ImportPreviewRegistry::new();
    let bytes = std::fs::read("../../tests/fixtures/qr/otpauth_multi.png").unwrap();
    let err = preview_import(&registry, &ImportInput::Image(bytes.clone(), None), &[]).unwrap_err();
    assert!(matches!(err, clavis_core::CoreError::InvalidInput(_)));
    // With an explicit selection the chosen candidate imports.
    let (_, preview) = preview_import(&registry, &ImportInput::Image(bytes, Some(0)), &[]).unwrap();
    assert_eq!(preview.issuer.as_deref(), Some("Example"));
}
