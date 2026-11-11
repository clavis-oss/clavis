# Clavis mobile (phase 9 scaffold)

This directory holds the React Native clients. In this release it contains
only the typed native-module contract (`specs/NativeClavis.ts`) and this
note — the mobile release phase builds on:

- `crates/clavis-ffi`: the UniFFI bridge (Kotlin/Swift) with the
  `core_info()` contract test (`format_version == 1`).
- The shared core, format and sync fixtures used by desktop and CLI.

Building the mobile clients requires Android Studio (Kotlin toolchain) and
Xcode (Swift toolchain); see `docs/mobile/build.md`. The mobile phase's own
release gates (real-device lifecycle, camera permission fallback, OAuth
round trips, accessibility) are listed in the development plan.
