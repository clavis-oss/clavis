/**
 * CoreClient bridge. The native session handle is local to one bridge
 * instance; error translation produces fixed safe messages — never raw
 * provider responses or Rust Debug output. Lock events bump a generation so
 * in-flight responses are discarded instead of repopulating a locked UI.
 */

import type {
  AccountCodeDto,
  AccountSummaryDto,
  ConflictDetailDto,
  ImportPreviewDto,
  ManualEntryDto,
  OtpCodeDto,
  SyncStatusKind,
  VaultInfoDto,
} from "@clavis/contracts";

export interface CoreClient {
  vaultInfo(): Promise<VaultInfoDto>;
  createVault(passphrase: string): Promise<VaultInfoDto>;
  confirmRecovery(recoveryKey: string): Promise<string>;
  unlock(passphrase: string): Promise<VaultInfoDto>;
  lock(): Promise<void>;
  listAccounts(): Promise<AccountSummaryDto[]>;
  /** Live codes for all usable accounts; poll every second while unlocked. */
  listCodes(): Promise<AccountCodeDto[]>;
  getCode(accountId: string): Promise<OtpCodeDto>;
  previewImportUri(uri: string): Promise<ImportPreviewDto>;
  previewImportImage(image: number[], selection?: number): Promise<ImportPreviewDto>;
  previewImportManual(entry: ManualEntryDto): Promise<ImportPreviewDto>;
  confirmImport(handle: number): Promise<AccountSummaryDto>;
  updateAccount(
    accountId: string,
    patch: { issuer?: string; accountLabel?: string; favorite?: boolean },
  ): Promise<void>;
  deleteAccount(accountId: string): Promise<void>;
  restoreAccount(accountId: string): Promise<void>;
  listConflicts(): Promise<ConflictDetailDto[]>;
  resolveConflict(accountId: string, field: string, candidateIndex: number): Promise<void>;
  keepBoth(accountId: string, field: string, keepOriginal: number, keepNew: number): Promise<void>;
  exportVault(destination: string): Promise<string>;
  connectProviderBegin(provider: string): Promise<string>;
  connectProviderComplete(provider: string, callbackUrl: string): Promise<VaultInfoDto>;
  disconnectProvider(provider: string): Promise<void>;
  syncNow(): Promise<SyncStatusKind>;
  getSyncStatus(): Promise<SyncStatusKind>;
}

/** Fixed safe message for any command failure. Only the DTO shape
 * { kind, message } produced by our own commands is trusted; anything else
 * (raw Errors, provider output, Rust Debug strings) renders generically. */
export function safeErrorMessage(err: unknown): string {
  if (
    err &&
    typeof err === "object" &&
    "kind" in err &&
    "message" in err &&
    typeof (err as { message: unknown }).message === "string"
  ) {
    return (err as { message: string }).message;
  }
  return "Something went wrong. Technical details are available separately.";
}

/**
 * Wraps a client so that responses completing after a lock event are
 * discarded: the caller sees `{ discarded: true }` and the UI never
 * repopulates a locked screen.
 */
export type Guarded<T> = { discarded: true; value?: undefined } | { discarded: false; value: T };

export function guardAgainstLock(client: CoreClient) {
  let generation = 1;
  const listeners = new Set<() => void>();
  const wrap = <Args extends unknown[], R>(
    op: (...args: Args) => Promise<R>,
  ): ((...args: Args) => Promise<Guarded<R>>) => {
    return async (...args: Args) => {
      const gen = generation;
      const value = await op(...args);
      if (gen !== generation) {
        return { discarded: true };
      }
      return { discarded: false, value };
    };
  };
  return {
    async lock(): Promise<void> {
      await client.lock();
      generation += 1;
      listeners.forEach((l) => l());
    },
    onLock(listener: () => void): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    generation(): number {
      return generation;
    },
    raw: client,
    guarded: {
      vaultInfo: wrap(client.vaultInfo.bind(client)),
      unlock: wrap(client.unlock.bind(client)),
      listAccounts: wrap(client.listAccounts.bind(client)),
      listCodes: wrap(client.listCodes.bind(client)),
      getCode: wrap(client.getCode.bind(client)),
      listConflicts: wrap(client.listConflicts.bind(client)),
      getSyncStatus: wrap(client.getSyncStatus.bind(client)),
      syncNow: wrap(client.syncNow.bind(client)),
      previewImportUri: wrap(client.previewImportUri.bind(client)),
      previewImportManual: wrap(client.previewImportManual.bind(client)),
      confirmImport: wrap(client.confirmImport.bind(client)),
    },
  };
}

export type GuardedClient = ReturnType<typeof guardAgainstLock>;

/** Tauri IPC bridge used in the packaged app. */
export function tauriClient(): CoreClient {
  const invoke = async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
    return tauriInvoke<T>(cmd, args);
  };
  return {
    vaultInfo: () => invoke("vault_info"),
    createVault: (passphrase) => invoke("create_vault", { passphrase }),
    confirmRecovery: (recoveryKey) => invoke("confirm_recovery", { recoveryKey }),
    unlock: (passphrase) => invoke("unlock", { passphrase }),
    lock: () => invoke("lock"),
    listAccounts: () => invoke("list_accounts"),
    listCodes: () => invoke("list_codes"),
    getCode: (accountId) => invoke("get_code", { accountId }),
    previewImportUri: (uri) => invoke("preview_import_uri", { uri }),
    previewImportImage: (image, selection) =>
      invoke("preview_import_image", { image, selection: selection ?? null }),
    previewImportManual: (entry) => invoke("preview_import_manual", { entry }),
    confirmImport: (handle) => invoke("confirm_import", { handle }),
    updateAccount: (accountId, patch) =>
      invoke("update_account", {
        accountId,
        issuer: patch.issuer ?? null,
        accountLabel: patch.accountLabel ?? null,
        favorite: patch.favorite ?? null,
      }),
    deleteAccount: (accountId) => invoke("delete_account", { accountId }),
    restoreAccount: (accountId) => invoke("restore_account", { accountId }),
    listConflicts: () => invoke("list_conflicts"),
    resolveConflict: (accountId, field, candidateIndex) =>
      invoke("resolve_conflict", { accountId, field, candidateIndex }),
    keepBoth: (accountId, field, keepOriginal, keepNew) =>
      invoke("keep_both", { accountId, field, keepOriginal, keepNew }),
    exportVault: (destination) => invoke("export_vault", { destination }),
    connectProviderBegin: (provider) => invoke("connect_provider_begin", { provider }),
    connectProviderComplete: (provider, callbackUrl) =>
      invoke("connect_provider_complete", { provider, callbackUrl }),
    disconnectProvider: (provider) => invoke("disconnect_provider", { provider }),
    syncNow: () => invoke("sync_now"),
    getSyncStatus: () => invoke("get_sync_status"),
  };
}
