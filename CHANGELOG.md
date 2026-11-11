# Changelog

## 0.1.0-beta.1 — 2026-10-31

Initial implementation of phases 1-7 core.

- **Vault format (`clavis-v1`)**: `CLVS` container layout, Argon2id
  64 MiB / 3 / 4 + HKDF-SHA-256 domain separation, XChaCha20-Poly1305
  payload and key slots, passphrase and recovery key slots, header and
  object limits, reader KDF caps, duplicate-field rejection.
- **Causal state**: observed-remove multi-value registers per account
  field, deterministic merge, explicit conflict resolution, atomic OTP
  config.
- **Local store**: encrypted SQLite with device key, durability and
  sentinel behavior.
- **Sync engine**: `RemoteStore` transport contract, immutable
  revisions with idempotent create and digest verification, graph
  validation, 750 ms debounce / 60 s poll / backoff with jitter.
- **Providers**: OAuth PKCE S256 with loopback callbacks; Google Drive
  (`drive.file`), OneDrive (`Files.ReadWrite.AppFolder`), Dropbox
  (App Folder) adapters at contract-test level.
- **Standalone export**: `CLVX` container with dedicated payload
  domain, lossless causal state, fresh namespace on restore; recovery
  and migration flow (prepare/verify/retire/activate).
- **CLI + TUI**: init/connect/list/code/add/sync/export/recover/tui/
  doctor, stable exit codes (0/2/3/4/5), no secrets via argv/env,
  ratatui TUI state machine.
- **Desktop**: Tauri 2 app with restrictive CSP and minimal
  capabilities; React 19 UI with design tokens; 11 frontend tests.
- **Contracts**: ts-rs DTO generation into `packages/contracts`,
  drift-checked by `scripts/check-contract-drift.mjs`.
- **UniFFI bridge**: `core_info()` contract (`format_version = 1`),
  spike-level for the mobile phase.
- **Docs**: ADRs 0001-0006, security documentation set, provider
  guides, release evidence phases 01-07.

### Pending external gates

- Provider production registrations/approvals and live smoke tests
  (`docs/providers/*.md`).
- Independent crypto review and fuzz campaign before beta
  distribution (`docs/release/desktop-v1-checklist.md`).
- macOS, Windows, and mobile remain unreleased
  (`docs/adr/0001-platform-baseline.md`, `docs/windows/build.md`,
  `docs/mobile/build.md`).
