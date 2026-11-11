# Real provider sync scenarios (manual)

**Requires real accounts and explicit opt-in.** These scenarios hit
live Google Drive, OneDrive, and Dropbox. They are not automated, not
part of CI, and should only be run by a maintainer or a contributor
who accepts that test revisions are written to their personal storage
account. Use a dedicated test account where possible. Never run with a
vault containing real OTP seeds.

Repeat the script below once per provider (Google, OneDrive, Dropbox),
with development client IDs from the `CLAVIS_*_CLIENT_ID` environment
variables.

## Script

1. **Connect**
   - Machine A: `clavis init`, then `clavis connect <provider>`; complete
     the browser OAuth; confirm the loopback callback succeeds.
2. **Offline adds on both sides**
   - Machine A (offline): `clavis add` two accounts.
   - Machine B (set up by restoring A's export or by cloning the local
     store): go offline, `clavis add` two different accounts.
3. **Sync both orders**
   - Machine A online, sync, then B online, sync. Record final state.
   - Reset; repeat with B syncing first. Both orders must converge to
     identical state (permutation invariance on real storage).
4. **Deliberate conflict**
   - A and B offline edit the same account's issuer differently; sync
     both. Expect a conflict card on both; resolve on one; sync; expect
     convergence.
5. **Delete-vs-edit**
   - A offline deletes an account; B offline edits its label; sync
     both; expect the documented delete-vs-edit outcome
     (`tests/scenarios/sync_cases.json`).
6. **Revoke**
   - Revoke Clavis's access in the provider's account settings.
   - `clavis sync` must fail cleanly (exit 4) with a reconnect hint,
     no data loss, no crash.
7. **Restore export**
   - `clavis export out.clvx` on A; on a clean machine `clavis recover
     out.clvx`; confirm a fresh namespace, full account set, and no
     reuse of the old vault_id.

## Record

For each provider, record: date, client ID provenance (dev env var),
per-step results, and deviations, in
`docs/release/evidence/` (a new evidence file) — these runs are part
of the live smoke tests pending in phase-05 evidence.
