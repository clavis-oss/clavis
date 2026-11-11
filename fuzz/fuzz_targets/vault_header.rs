//! Fuzz target: `clavis-v1` container parsing.
//!
//! Exercises `parse_container` with arbitrary bytes. The parser must
//! bound-check before allocating or deriving keys and must never panic:
//! every input is either a valid container or a typed error.
//!
//! Note: this target will not compile without cargo-fuzz (libFuzzer
//! nightly tooling). That is expected; see ../README.md.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parsing must be panic-free and side-effect-free for any input.
    // All failures must be typed errors, never aborts.
    let _ = clavis_core::vault::format::parse_container(data);
});
