# Fuzzing

cargo-fuzz targets for Clavis's untrusted-input parsers. **These are
not built or run as part of normal CI or `cargo test`**; they require
cargo-fuzz and a nightly toolchain, so attempts to build them with a
stable toolchain will fail to compile — that is expected.

## Targets

| Target | Entry point | Invariant |
|---|---|---|
| `vault_header` | `clavis_core::vault::format::parse_container` | Parsing arbitrary bytes never panics, never allocates unboundedly, never performs KDF work before bound checks. |
| `otpauth` | `clavis_core::import::uri::parse_otpauth_uri` | Parsing arbitrary strings never panics; malformed input is a typed error. |

## Running

```sh
cargo install cargo-fuzz
cd fuzz
cargo fuzz run vault_header -- -max_total_time=600
cargo fuzz run otpauth -- -max_total_time=600
```

Crashes are written to `artifacts/` and become regression tests in the
respective crate's test suite.

## Status

Targets exist; **no sustained campaign has been run yet** (tracked as
a phase-3 gate in `docs/release/evidence/phase-03.md` and the desktop
v1 checklist).
