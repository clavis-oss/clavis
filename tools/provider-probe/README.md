# provider-probe

A planned diagnostic tool that exercises one storage-provider adapter
at a time against a real (or fake) remote, to distinguish "Clavis sync
is broken" from "the provider changed".

**Not implemented as code yet.** This README records the plan; there is
no binary in this directory today.

## Planned probes

Per provider (Google Drive, OneDrive, Dropbox, and the WebDAV adapter):

1. **create** — upload one file with synthetic bytes.
2. **list** — list and confirm the probe file appears, including
   paginated listings (force pagination by generating more objects
   than one page holds).
3. **download/compare** — re-download and byte-compare, matching the
   sync engine's digest-verification step.
4. **duplicate handling** — create a second object with the same name:
   byte-identical content must be accepted; differing content must
   fail, never overwrite.
5. **token refresh/revocation** — verify a refresh round-trip works,
   then revoke access and confirm a clean failure (no retry storm, no
   data written).
6. **quota simulation** — against fake endpoints, return quota/`507`
   style responses and confirm the scheduler backs off and honors
   `Retry-After`.

## Hard rules

- Probes store **synthetic bytes only** — no vault contents, no real
  OTP seeds, nothing read from a user's Clavis vault. A probe file is
  clearly named (e.g. `clavis-probe/<timestamp>.bin`) and deleted after
  the run.
- Probes must never modify or delete objects they did not create in
  that run.

## Status

Plan only. Implementation is unscheduled; the sync engine's fake
remote covers the contract tests in the meantime
(`crates/clavis-sync/src/fake_remote.rs`).
