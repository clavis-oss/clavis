/**
 * Deterministic fake CoreClient for component tests and UI fixtures. All
 * shown accounts and codes are fictional synthetic data.
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
import type { CoreClient } from "./bridge";

export class FakeCoreClient implements CoreClient {
  vault: VaultInfoDto = {
    vault_id: "",
    name: null,
    provider_kind: null,
    locked: true,
    has_conflicts: false,
  };
  accounts: AccountSummaryDto[] = [];
  conflicts: ConflictDetailDto[] = [];
  status: SyncStatusKind = "local_only";
  unlockAttempts = 0;
  failUnlock = false;
  created = 0;
  /** Test knobs: delay list/code responses to simulate in-flight calls. */
  delayListMs = 0;
  delayCodeMs = 0;
  /** Simulate an image containing N QR codes for the image import tests. */
  multiQrCandidates = 1;
  private nextPreviewHandle = 1;
  private previews = new Map<number, ImportPreviewDto>();
  /** Deterministic per-account code that rotates every 30s of test time. */
  codeFor(accountId: string): string {
    const step = Math.floor(Date.now() / 30_000);
    const n = (parseInt(accountId.slice(-4), 16) + step) % 1_000_000;
    return String(n).padStart(6, "0");
  }

  async vaultInfo(): Promise<VaultInfoDto> {
    return { ...this.vault };
  }

  async createVault(): Promise<VaultInfoDto> {
    this.created += 1;
    this.vault = {
      vault_id: "00000000-0000-0000-0000-0000000000aa",
      name: "Vault",
      provider_kind: null,
      locked: false,
      has_conflicts: false,
    };
    return { ...this.vault };
  }

  async confirmRecovery(): Promise<string> {
    return "ok";
  }

  async unlock(passphrase: string): Promise<VaultInfoDto> {
    this.unlockAttempts += 1;
    if (this.failUnlock || passphrase.length < 12) {
      throw { kind: "invalid_credential_or_data", message: "Could not unlock this vault. Check your passphrase or try a backup." };
    }
    this.vault.locked = false;
    return { ...this.vault };
  }

  async lock(): Promise<void> {
    this.vault.locked = true;
  }

  async listAccounts(): Promise<AccountSummaryDto[]> {
    if (this.vault.locked) {
      throw { kind: "locked", message: "vault is locked" };
    }
    if (this.delayListMs > 0) {
      await new Promise((r) => setTimeout(r, this.delayListMs));
    }
    return this.accounts.map((a) => ({ ...a }));
  }

  async listCodes(): Promise<AccountCodeDto[]> {
    if (this.vault.locked) {
      throw { kind: "locked", message: "vault is locked" };
    }
    const now = Date.now();
    return this.accounts
      .filter((a) => !a.deleted && !a.has_conflict)
      .map((a) => ({
        account_id: a.id,
        value: this.codeFor(a.id),
        valid_until_unix_ms: String(now + 20_000),
      }));
  }

  async getCode(accountId: string): Promise<OtpCodeDto> {
    if (this.vault.locked) {
      throw { kind: "locked", message: "vault is locked" };
    }
    if (this.delayCodeMs > 0) {
      await new Promise((r) => setTimeout(r, this.delayCodeMs));
    }
    const account = this.accounts.find((a) => a.id === accountId);
    if (account?.has_conflict) {
      throw { kind: "invalid_input", message: "account OTP configuration is conflicted" };
    }
    return { value: "123456", valid_until_unix_ms: "1800000" };
  }

  async previewImportUri(uri: string): Promise<ImportPreviewDto> {
    if (!uri.startsWith("otpauth://totp/")) {
      throw { kind: "invalid_input", message: "unsupported URI scheme" };
    }
    const handle = this.nextPreviewHandle++;
    const preview: ImportPreviewDto = {
      handle,
      issuer: "Example",
      account_label: "user@example.com",
      algorithm: "Sha1",
      digits: 6,
      period_seconds: 30,
      duplicate_warning: this.accounts.length > 0,
    };
    this.previews.set(handle, preview);
    return preview;
  }

  async previewImportManual(entry: ManualEntryDto): Promise<ImportPreviewDto> {
    const handle = this.nextPreviewHandle++;
    const preview: ImportPreviewDto = {
      handle,
      issuer: entry.issuer || null,
      account_label: entry.account_label,
      algorithm: entry.algorithm,
      digits: entry.digits,
      period_seconds: entry.period_seconds,
      duplicate_warning: false,
    };
    this.previews.set(handle, preview);
    return preview;
  }

  async confirmImport(handle: number): Promise<AccountSummaryDto> {
    const preview = this.previews.get(handle);
    if (!preview) throw { kind: "invalid_input", message: "unknown or expired import preview" };
    this.previews.delete(handle);
    const account: AccountSummaryDto = {
      id: `00000000-0000-0000-0000-${String(this.accounts.length + 1).padStart(12, "0")}`,
      issuer: preview.issuer,
      account_label: preview.account_label,
      favorite: false,
      has_conflict: false,
      conflicted_fields: [],
      deleted: false,
    };
    this.accounts.push(account);
    return account;
  }

  async updateAccount(accountId: string, patch: { favorite?: boolean; accountLabel?: string }): Promise<void> {
    const a = this.accounts.find((x) => x.id === accountId);
    if (!a) throw { kind: "invalid_input", message: "unknown account" };
    if (patch.favorite !== undefined) a.favorite = patch.favorite;
    if (patch.accountLabel !== undefined) a.account_label = patch.accountLabel;
  }

  async deleteAccount(accountId: string): Promise<void> {
    this.accounts = this.accounts.filter((a) => a.id !== accountId);
  }

  async restoreAccount(_accountId: string): Promise<void> {}

  async previewImportImage(image: number[], selection?: number): Promise<ImportPreviewDto> {
    if (image.length === 0) {
      throw { kind: "invalid_input", message: "unreadable image" };
    }
    if (selection === undefined && this.multiQrCandidates > 1) {
      throw {
        kind: "multiple_candidates",
        message: `This image contains ${this.multiQrCandidates} QR codes — select one.`,
      };
    }
    return this.previewImportUri("otpauth://totp/Fixture%3Asynthetic");
  }

  async listConflicts(): Promise<ConflictDetailDto[]> {
    return this.conflicts;
  }

  async resolveConflict(_accountId: string, _field: string, _index: number): Promise<void> {
    this.conflicts = [];
    this.accounts.forEach((a) => (a.has_conflict = false));
    this.vault.has_conflicts = false;
  }

  async keepBoth(accountId: string, _field: string, keepOriginal: number, keepNew: number): Promise<void> {
    const a = this.accounts.find((x) => x.id === accountId);
    if (a && keepOriginal !== keepNew) {
      this.accounts.push({
        ...a,
        id: "00000000-0000-0000-0000-0000000000bb",
        account_label: keepNew === 1 ? "kept B" : a.account_label,
      });
    }
    this.conflicts = [];
  }

  async exportVault(destination: string): Promise<string> {
    return destination;
  }

  async connectProviderBegin(_provider: string): Promise<string> {
    return "https://provider.example/oauth?state=fixture";
  }

  async connectProviderComplete(_provider: string, callbackUrl: string): Promise<VaultInfoDto> {
    if (!callbackUrl.includes("state=")) {
      throw { kind: "invalid_input", message: "state mismatch" };
    }
    this.vault.provider_kind = "google_drive";
    return { ...this.vault };
  }

  async disconnectProvider(): Promise<void> {
    this.vault.provider_kind = null;
  }

  async syncNow(): Promise<SyncStatusKind> {
    this.status = this.vault.provider_kind ? "synced" : "local_only";
    return this.status;
  }

  async getSyncStatus(): Promise<SyncStatusKind> {
    return this.status;
  }
}
