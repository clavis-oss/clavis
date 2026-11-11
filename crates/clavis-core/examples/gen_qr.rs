// One-off generator for tests/fixtures/qr/*.png (synthetic data only).
fn main() {
    use image::Luma;
    use qrcode::QrCode;
    let uris = [
        ("otpauth_example.png", "otpauth://totp/Example%3Asynthetic%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
        ("otpauth_multicandidate.png", "otpauth://totp/Fixture%3Asynthetic?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Fixture"),
    ];
    for (name, uri) in uris {
        let code = QrCode::new(uri.as_bytes()).unwrap();
        let img = code.render::<Luma<u8>>().quiet_zone(true).build();
        img.save(format!("tests/fixtures/qr/{name}")).unwrap();
        println!("wrote tests/fixtures/qr/{name}");
    }
}
