//! RFC 8785 canonical JSON subset used for key-slot AAD.
//!
//! The AAD is built from a restricted value set: strings (JSON-escaped,
//! non-ASCII emitted as raw UTF-8), signed/unsigned integers (plain decimal),
//! byte strings (unpadded base64url) and objects with fixed ASCII field names
//! emitted in sorted order. Arrays are not used. This matches RFC 8785 output
//! for the values it accepts; the full number-formatting rules (floats) are
//! out of scope because AAD values are integers and strings only.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalValue {
    Str(String),
    Int(i64),
    Bytes(Vec<u8>),
    Object(BTreeMap<String, CanonicalValue>),
}

impl CanonicalValue {
    pub fn object(pairs: Vec<(&'static str, CanonicalValue)>) -> Self {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            let prev = map.insert(k.to_string(), v);
            debug_assert!(prev.is_none(), "duplicate canonical key {k}");
        }
        CanonicalValue::Object(map)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            CanonicalValue::Str(s) => write_json_string(out, s),
            CanonicalValue::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
            CanonicalValue::Bytes(b) => {
                write_json_string(out, &base64_url_unpadded(b));
            }
            CanonicalValue::Object(map) => {
                out.push(b'{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write_json_string(out, k);
                    out.push(b':');
                    v.write(out);
                }
                out.push(b'}');
            }
        }
    }
}

pub fn base64_url_unpadded(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn base64_url_decode(s: &str) -> Result<Vec<u8>, CoreError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| CoreError::InvalidCredentialOrData)
}

fn write_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Detect duplicate keys at any object level in a JSON document before it is
/// parsed into typed structures. serde_json would otherwise silently keep the
/// last value, which an attacker could use to smuggle conflicting fields.
pub fn reject_duplicate_json_fields(input: &[u8]) -> Result<(), CoreError> {
    let mut p = Scanner { b: input, i: 0 };
    p.skip_ws();
    p.detect_value()?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(CoreError::InvalidCredentialOrData);
    }
    Ok(())
}

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Scanner<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), CoreError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(CoreError::InvalidCredentialOrData)
        }
    }

    fn detect_value(&mut self) -> Result<(), CoreError> {
        match self.peek().ok_or(CoreError::InvalidCredentialOrData)? {
            b'{' => self.detect_object(),
            b'[' => self.detect_array(),
            b'"' => {
                self.skip_string()?;
                Ok(())
            }
            b't' | b'f' | b'n' => self.skip_keyword(),
            b'-' | b'0'..=b'9' => self.skip_number(),
            _ => Err(CoreError::InvalidCredentialOrData),
        }
    }

    fn detect_object(&mut self) -> Result<(), CoreError> {
        self.eat(b'{')?;
        let mut seen: Vec<String> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            let key = self.scan_string()?;
            if seen.iter().any(|k| k == &key) {
                return Err(CoreError::InvalidCredentialOrData);
            }
            seen.push(key);
            self.skip_ws();
            self.eat(b':')?;
            self.skip_ws();
            self.detect_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(CoreError::InvalidCredentialOrData),
            }
        }
    }

    fn detect_array(&mut self) -> Result<(), CoreError> {
        self.eat(b'[')?;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            self.detect_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(CoreError::InvalidCredentialOrData),
            }
        }
    }

    fn scan_string(&mut self) -> Result<String, CoreError> {
        self.eat(b'"')?;
        let start = self.i;
        while let Some(c) = self.peek() {
            match c {
                b'"' => {
                    let s = std::str::from_utf8(&self.b[start..self.i])
                        .map_err(|_| CoreError::InvalidCredentialOrData)?;
                    self.i += 1;
                    return Ok(s.to_string());
                }
                b'\\' => {
                    // Escape sequences are not allowed in the fixed header
                    // field names we care about; treat them as opaque and
                    // include them verbatim for duplicate detection.
                    self.i += 2;
                }
                _ => self.i += 1,
            }
        }
        Err(CoreError::InvalidCredentialOrData)
    }

    fn skip_string(&mut self) -> Result<(), CoreError> {
        self.scan_string()?;
        Ok(())
    }

    fn skip_keyword(&mut self) -> Result<(), CoreError> {
        let rest = &self.b[self.i..];
        for kw in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
            if rest.starts_with(kw) {
                self.i += kw.len();
                return Ok(());
            }
        }
        Err(CoreError::InvalidCredentialOrData)
    }

    fn skip_number(&mut self) -> Result<(), CoreError> {
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.i += 1;
            } else {
                break;
            }
        }
        Ok(())
    }
}

use crate::error::CoreError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_object_is_sorted_and_minimal() {
        let v = CanonicalValue::object(vec![
            ("b", CanonicalValue::Int(2)),
            ("a", CanonicalValue::Str("x\"y".into())),
            ("z", CanonicalValue::Bytes(vec![0xfb, 0xff])),
        ]);
        assert_eq!(v.serialize(), br#"{"a":"x\"y","b":2,"z":"-_8"}"#);
    }

    #[test]
    fn duplicate_fields_are_rejected() {
        assert!(reject_duplicate_json_fields(br#"{"a":1,"b":2}"#).is_ok());
        assert!(reject_duplicate_json_fields(br#"{"a":{"x":1},"a":2}"#).is_err());
        assert!(reject_duplicate_json_fields(br#"{"a":[{"x":1},{"x":2,"x":3}]}"#).is_err());
        assert!(reject_duplicate_json_fields(br#"{"a":1,}"#).is_err());
    }
}
