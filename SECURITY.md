# Security policy

## Supported versions

| Version | Support |
|---|---|
| 0.1.0-beta.x | Supported (current development line) |

Older or unpublished builds receive no security support.

## Reporting a vulnerability

Report privately by email to **security@clavis.invalid**
(maintainer placeholder address; see the repository for the current
address). Do **not** open a public issue for anything you believe is a
vulnerability, and do not disclose before a fix and a coordinated
advisory exist.

Please include:

- Affected component (vault format, sync protocol, a specific client,
  the desktop bridge) and version/commit.
- A reproduction: inputs, commands, or a minimal test case.
- Impact as you understand it, including what an attacker needs
  (device access? storage account access? network position?).
- Any suggested fix, if you have one.

We will acknowledge within 5 business days and aim to reach a
resolution decision within 90 days of a validated report (coordinated
disclosure target). We will credit reporters by name unless they
prefer otherwise.

## Scope notes

In scope:

- The `clavis-v1` vault format and its crypto (key schedule, AAD
  bindings, KDF caps, failure behavior).
- The sync protocol and its remote-store assumptions
  (`docs/security/sync-protocol-v1.md`).
- The clients (CLI, TUI, desktop) and the Tauri command/capability
  surface.

Known, documented boundaries (not vulnerabilities by themselves, but
tell us if you think a boundary is drawn in the wrong place):

- Unlocked-OS compromise, screen recording, clipboard history (see
  `docs/security/threat-model.md`).
- JS memory not being reliably zeroable in the desktop webview.
- Fresh-install rollback detection limits in the sync protocol.
