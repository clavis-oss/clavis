# Clavis

Clavis is a local-first TOTP authenticator. Your codes live in an
encrypted vault on your devices and sync — still encrypted — through
**your own** storage account (Google Drive, OneDrive, or Dropbox).
There are no Clavis accounts and no telemetry.

- Rust core (`clavis-v1` encrypted vault format: Argon2id 64 MiB / 3
  passes / 4 lanes, HKDF-SHA-256 domain separation, XChaCha20-Poly1305).
- Causal merge (observed-remove registers per account field): offline
  edits on several devices converge without silent overwrites; conflicts
  are resolved explicitly, never by "last write wins".
- Clients: CLI + TUI (ratatui) and a Tauri 2 desktop app (React 19).
  Linux x86_64 is the supported platform today.

## Quick start

Requirements: Linux x86_64 with `webkit2gtk-4.1` for the desktop app.
The Rust toolchain is pinned by `rust-toolchain.toml` (1.99.1); Node 24
and pnpm 12 are used for the frontend.

```sh
git clone <repo-url> clavis && cd clavis
pnpm install
cargo test --workspace                        # 146 tests
pnpm --filter @clavis/desktop dev             # desktop app (dev)
cargo run -p clavis-cli -- --help             # CLI entry point
```

## Repository layout

| Path | What it is |
|---|---|
| `crates/clavis-core` | Vault format, crypto, OTP engine, causal state, import. |
| `crates/clavis-store` | Local encrypted SQLite store. |
| `crates/clavis-sync` | Sync engine: transport contract, graph, merge, scheduler. |
| `crates/clavis-providers` | OAuth PKCE + Google Drive / OneDrive / Dropbox adapters. |
| `crates/clavis-cli` | CLI and TUI clients. |
| `crates/clavis-ffi` | UniFFI bridge (mobile phase, spike). |
| `apps/desktop` | Tauri 2 desktop app (`src-tauri`) + React UI (`src`). |
| `packages/contracts` | ts-rs generated DTOs (`src/generated/`), drift-checked. |
| `packages/design-tokens` | Shared design tokens. |
| `docs/` | ADRs, security docs, provider docs, release evidence. |
| `tests/` | Cross-crate fixtures and sync scenarios. |
| `fuzz/` | cargo-fuzz targets (not run as part of CI). |

## Security

Start with:

- `docs/security/vault-format-v1.md` — full wire format spec.
- `docs/security/threat-model.md` — what Clavis does and does not
  defend against.
- `docs/security/recovery.md`, `docs/security/sync-protocol-v1.md`,
  `docs/security/limitations.md`.

To report a vulnerability, see `SECURITY.md` (private disclosure).

## Status (honest)

Implemented — phases 1-7 core functionality:

- Vault format, crypto, recovery, export/migration.
- Causal merge and local store; sync engine with fake-remote coverage.
- Provider adapters (Google/OneDrive/Dropbox) at contract level.
- CLI, TUI, and desktop app on Linux.

Pending external gates (tracked in `docs/release/desktop-v1-checklist.md`):

- Provider production registrations/approvals and live-account smoke
  tests.
- macOS / Windows / mobile releases (see ADR 0001,
  `docs/windows/build.md`, `docs/mobile/build.md`).
- Independent security review before any beta distribution.

## License

Apache-2.0. See `LICENSE`.
