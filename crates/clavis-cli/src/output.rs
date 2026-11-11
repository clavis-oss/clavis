//! Terminal output helpers. Codes are the only secret-derived values ever
//! printed, and only on explicit invocation; labels never appear in errors
//! and seeds never appear anywhere.

/// Group an OTP code for display: `123 456` or `1234 5678`.
pub fn group_code(code: &str) -> String {
    if code.len() == 8 {
        format!("{} {}", &code[..4], &code[4..])
    } else if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

pub fn format_summary(
    id: &str,
    issuer: &Option<String>,
    label: &Option<String>,
    favorite: bool,
) -> String {
    let name = match (issuer, label) {
        (Some(i), Some(l)) => format!("{} · {}", i, l),
        (Some(i), None) => i.clone(),
        (None, Some(l)) => l.clone(),
        (None, None) => "<unnamed>".to_string(),
    };
    format!("{}  {}{}", id, name, if favorite { "  ★" } else { "" })
}
