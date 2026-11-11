/**
 * NativeClavis — typed TurboModule contract for the React Native bridge
 * (phase 9). Surface rules from the plan:
 * - Session identifiers are opaque strings across JS.
 * - u64 timestamps cross the bridge as decimal strings.
 * - No Rust pointer, root key, decoded seed or OAuth token is exposed to JS.
 * - All KDF, database, QR-decode and network work runs on an async worker,
 *   never the UI thread.
 *
 * This file is the codegen source for the native adapters; the full module
 * implementation lands in the mobile phase after the UniFFI spike is
 * validated on-device (see docs/adr/0003-native-bridge.md).
 */
export interface Spec extends TurboModule {
  // Phase-1 spike contract: every client must agree on the format version.
  coreInfo(): Promise<{ formatVersion: number }>;

  // Vault lifecycle (opaque session handles; never serialized keys).
  createVault(passphrase: string): Promise<{ vaultId: string }>;
  unlock(vaultId: string, passphrase: string): Promise<{ sessionHandle: string }>;
  lock(sessionHandle: string): Promise<void>;

  // Accounts — safe DTOs only, decimal-string timestamps.
  listAccounts(sessionHandle: string): Promise<string>; // JSON AccountSummaryDto[]
  getCode(sessionHandle: string, accountId: string): Promise<{ value: string; validUntilUnixMs: string }>;
}

export default TurboModuleRegistry.getEnforcing<Spec>("NativeClavis");
