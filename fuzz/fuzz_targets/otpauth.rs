//! Fuzz target: otpauth URI parsing.
//!
//! Exercises `parse_otpauth_uri` with arbitrary strings. Malformed,
//! oversized, or hostile URIs must produce typed errors, never panics
//! and never silently accepted secrets.
//!
//! Note: this target will not compile without cargo-fuzz (libFuzzer
//! nightly tooling). That is expected; see ../README.md.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = clavis_core::import::uri::parse_otpauth_uri(data);
});
