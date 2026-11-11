//! Path safety for WebDAV: all remote paths must stay beneath the
//! user-selected root. No `..` traversal, no absolute escapes, no scheme
//! changes.

use clavis_core::error::CoreError;

/// Join `segments` beneath `root`, rejecting traversal and empty segments
/// that could escape the root.
pub fn join_beneath_root(root: &str, segments: &str) -> Result<String, CoreError> {
    let root = root.trim_end_matches('/');
    if !root.starts_with('/') {
        return Err(CoreError::InvalidInput(
            "remote root must be an absolute path",
        ));
    }
    let mut out = root.to_string();
    for seg in segments.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(CoreError::InvalidInput("path traversal is not allowed"));
        }
        if seg.contains('\\') {
            return Err(CoreError::InvalidInput("invalid path character"));
        }
        out.push('/');
        out.push_str(seg);
    }
    Ok(out)
}

/// Build an absolute URL from the base and a server path, never changing the
/// scheme or host.
pub fn url_from_base(base_url: &str, server_path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let p = if server_path.starts_with('/') {
        server_path.to_string()
    } else {
        format!("/{}", server_path)
    };
    format!(
        "{}{}",
        base,
        p.split('/')
            .map(urlencode_path_segment)
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn urlencode_path_segment(s: &str) -> String {
    // Only encode characters unsafe in a URL path segment; keep '/' intact
    // by construction (segments never contain it here).
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal() {
        assert!(join_beneath_root("/clavis", "../etc/passwd").is_err());
        assert!(join_beneath_root("/clavis", "a/../../b").is_err());
        assert!(join_beneath_root("relative", "a").is_err());
    }

    #[test]
    fn keeps_paths_beneath_root() {
        assert_eq!(
            join_beneath_root("/remote.php/dav/files/alice/", "clavis/v/revisions/x.clv").unwrap(),
            "/remote.php/dav/files/alice/clavis/v/revisions/x.clv"
        );
    }
}
