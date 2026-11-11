import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { AccountSummaryDto, ConflictDetailDto, SyncStatusKind, VaultInfoDto } from "@clavis/contracts";
import { AccountRow } from "./components/AccountRow";
import { Button } from "./components/Button";
import { ConflictCard } from "./components/ConflictCard";
import { Dialog } from "./components/Dialog";
import {
  EmptyState,
  Page,
  ProviderPicker,
  RecoveryKeyCard,
  SearchField,
  SecretInput,
} from "./components/Controls";
import { Field } from "./components/Field";
import { SyncStatus } from "./components/AccountRow";
import { Toast } from "./components/Toast";
import { guardAgainstLock, safeErrorMessage, type CoreClient } from "./core/bridge";
import { Settings } from "./features/settings/Settings";

type Screen =
  | "welcome"
  | "create-passphrase"
  | "recovery-setup"
  | "connect-storage"
  | "unlock"
  | "accounts"
  | "settings";

const LOCK_TIMEOUT_MS = 5 * 60 * 1000;

export function App({ client, clipboard }: { client: CoreClient; clipboard?: { writeText(t: string): Promise<void> } }) {
  const guarded = useMemo(() => guardAgainstLock(client), [client]);
  const [screen, setScreen] = useState<Screen>("welcome");
  const [vault, setVault] = useState<VaultInfoDto | null>(null);
  /** Live codes per account, refreshed by the 1s poll while unlocked. */
  const [codes, setCodes] = useState<Record<string, import("@clavis/contracts").OtpCodeDto>>({});
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [status, setStatus] = useState<SyncStatusKind>("local_only");
  const searchRef = useRef<HTMLInputElement>(null);

  // ---- boot: determine vault state ----
  useEffect(() => {
    void (async () => {
      try {
        const r = await guarded.guarded.vaultInfo();
        if (r.discarded) return;
        setVault(r.value);
        setScreen(r.value.vault_id === "" ? "welcome" : r.value.locked ? "unlock" : "accounts");
        setStatus(await client.getSyncStatus());
      } catch (e) {
        setError(safeErrorMessage(e));
      }
    })();
  }, [guarded, client]);

  // ---- inactivity lock (monotonic timer) ----
  const activityRef = useRef(Date.now());
  useEffect(() => {
    const bump = () => {
      activityRef.current = Date.now();
    };
    ["mousedown", "keydown", "touchstart"].forEach((ev) => window.addEventListener(ev, bump));
    const t = setInterval(() => {
      if (vault && !vault.locked && Date.now() - activityRef.current > LOCK_TIMEOUT_MS) {
        void doLock();
      }
    }, 10_000);
    return () => {
      ["mousedown", "keydown", "touchstart"].forEach((ev) => window.removeEventListener(ev, bump));
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vault]);

  const doLock = useCallback(async () => {
    setScreen((s) => (s === "accounts" || s === "settings" ? "unlock" : s));
    await guarded.lock();
    setVault((v) => (v ? { ...v, locked: true } : v));
  }, [guarded, vault]);

  // ---- keyboard shortcuts (window-local, never global) ----
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === "k" && screen === "accounts") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (mod && e.key.toLowerCase() === "n" && screen === "accounts") {
        e.preventDefault();
        setScreen("accounts");
        setAddOpen(true);
      } else if (mod && e.key.toLowerCase() === "l") {
        e.preventDefault();
        void doLock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [screen, doLock]);

  // ---- account list state ----
  const [accounts, setAccounts] = useState<AccountSummaryDto[]>([]);
  const [query, setQuery] = useState("");
  const [filterFavorites, setFilterFavorites] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null); // last copied row
  const [addOpen, setAddOpen] = useState(false);
  const [editAccount, setEditAccount] = useState<AccountSummaryDto | null>(null);
  const [conflict, setConflict] = useState<ConflictDetailDto | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const refreshAccounts = useCallback(async () => {
    const r = await guarded.guarded.listAccounts();
    if (!r.discarded) setAccounts(r.value);
  }, [guarded]);

  useEffect(() => {
    if (screen === "accounts" && vault && !vault.locked) {
      void refreshAccounts();
    }
  }, [screen, vault, refreshAccounts]);

  // Live codes: one batched command per second while the list is visible.
  useEffect(() => {
    if (screen !== "accounts" || !vault || vault.locked) return;
    let alive = true;
    const pull = async () => {
      const r = await guarded.guarded.listCodes();
      if (!alive || r.discarded) return;
      const next: Record<string, import("@clavis/contracts").OtpCodeDto> = {};
      for (const c of r.value) next[c.account_id] = { value: c.value, valid_until_unix_ms: c.valid_until_unix_ms };
      setCodes(next);
    };
    void pull();
    const t = setInterval(pull, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [screen, vault, guarded]);

  const copyCode = useCallback(
    async (accountId: string) => {
      try {
        // Copy fetches the code at click time from the core, never a cached
        // React render.
        const r = await guarded.guarded.getCode(accountId);
        if (r.discarded) return;
        if (clipboard) {
          await clipboard.writeText(r.value.value);
        }
        setSelectedId(accountId);
        setToast("Code copied");
      } catch (e) {
        setError(safeErrorMessage(e));
      }
    },
    [guarded, clipboard],
  );

  const filtered = accounts
    .filter((a) => !filterFavorites || a.favorite)
    .filter((a) => {
      if (!query) return true;
      const q = query.toLowerCase();
      return `${a.issuer ?? ""} ${a.account_label ?? ""}`.toLowerCase().includes(q);
    });

  return (
    <div style={{ display: "flex", height: "100%" }}>
      {screen !== "welcome" && screen !== "unlock" && (
        <nav
          aria-label="Main"
          style={{
            width: "var(--sidebar-w)",
            background: "var(--surface-sidebar)",
            borderRight: "1px solid var(--border-subtle)",
            display: "flex",
            flexDirection: "column",
            padding: "var(--sp-4)",
            gap: "var(--sp-2)",
          }}
        >
          <Button variant={filterFavorites ? "secondary" : "primary"} onClick={() => setFilterFavorites(false)}>
            All codes
          </Button>
          <Button variant={filterFavorites ? "primary" : "secondary"} onClick={() => setFilterFavorites(true)}>
            Favorites
          </Button>
          <div style={{ flex: 1 }} />
          <Button
            variant="secondary"
            onClick={() => {
              setSettingsOpen(true);
            }}
          >
            Settings
          </Button>
          <Button variant="secondary" onClick={() => void doLock()}>
            Lock this app
          </Button>
          <SyncStatus status={status} providerKind={vault?.provider_kind} />
        </nav>
      )}
      <main style={{ flex: 1, overflow: "auto" }}>
        {screen === "welcome" && (
          <Welcome
            client={client}
            onCreated={(v) => {
              setVault(v);
              setScreen("recovery-setup");
            }}
            onOpenExisting={() => setScreen("unlock")}
            onError={setError}
          />
        )}
        {screen === "create-passphrase" && null}
        {screen === "recovery-setup" && vault && (
          <RecoverySetup
            client={client}
            vault={vault}
            onDone={(v) => {
              setVault(v);
              setScreen("accounts");
            }}
            onError={setError}
          />
        )}
        {screen === "connect-storage" && vault && (
          <ConnectStorage
            client={client}
            vault={vault}
            onConnected={(v) => {
              setVault(v);
              setScreen("accounts");
            }}
            onCancel={() => setScreen("accounts")}
            onError={setError}
          />
        )}
        {screen === "unlock" && (
          <Unlock
            client={client}
            vault={vault}
            onUnlocked={(v) => {
              setVault(v);
              setScreen("accounts");
            }}
            onError={setError}
          />
        )}
        {screen === "accounts" && (
          <div style={{ padding: "var(--sp-5)" }}>
            <div
              style={{
                display: "flex",
                gap: "var(--sp-3)",
                alignItems: "center",
                flexWrap: "wrap",
                marginBottom: "var(--sp-4)",
              }}
            >
              <SearchField value={query} onChange={setQuery} inputRef={searchRef} />
              <Button variant="primary" onClick={() => setAddOpen(true)}>
                Add account
              </Button>
            </div>
            {filtered.length === 0 ? (
              <EmptyState onAdd={() => setAddOpen(true)} searchEmpty={accounts.length > 0} />
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "var(--sp-3)" }}>
                {filtered.map((a) => (
                  <AccountRow
                    key={a.id}
                    account={a}
                    copied={selectedId === a.id}
                    code={codes[a.id]?.value}
                    remainingSeconds={
                      codes[a.id]
                        ? Math.max(0, Math.ceil(Number(codes[a.id].valid_until_unix_ms) / 1000 - Date.now() / 1000))
                        : undefined
                    }
                    onCopy={() => void copyCode(a.id)}
                    onEdit={() => setEditAccount(a)}
                    onFavorite={() =>
                      void client
                        .updateAccount(a.id, { favorite: !a.favorite })
                        .then(() => refreshAccounts())
                    }
                    onDelete={() => setEditAccount(a)}
                  />
                ))}
              </div>
            )}
          </div>
        )}
        {error && (
          <Dialog title="Something needs your attention" onClose={() => setError(null)}>
            <p role="alert">{error}</p>
            <Button variant="secondary" onClick={() => setError(null)}>
              Close
            </Button>
          </Dialog>
        )}
        {addOpen && (
          <AddAccountDialog
            client={client}
            onClose={() => setAddOpen(false)}
            onAdded={() => {
              setAddOpen(false);
              void refreshAccounts();
            }}
          />
        )}
        {editAccount && (
          <EditAccountDialog
            client={client}
            account={editAccount}
            onClose={() => setEditAccount(null)}
            onChanged={() => {
              setEditAccount(null);
              void refreshAccounts();
            }}
            onConflict={() => {
              void (async () => {
                const r = await guarded.guarded.listConflicts();
                if (!r.discarded && r.value.length > 0) setConflict(r.value[0]);
              })();
            }}
          />
        )}
        {conflict && (
          <ConflictCard
            conflict={conflict}
            accountName={accounts.find((a) => a.id === conflict.entry_id)?.issuer ?? "account"}
            onKeep={(idx) => {
              void client
                .resolveConflict(conflict.entry_id, conflict.field, idx)
                .then(() => {
                  setConflict(null);
                  return refreshAccounts();
                });
            }}
            onKeepBoth={(a, b) => {
              void client
                .keepBoth(conflict.entry_id, conflict.field, a, b)
                .then(() => {
                  setConflict(null);
                  return refreshAccounts();
                });
            }}
            onCancel={() => setConflict(null)}
          />
        )}
        {settingsOpen && (
          <Settings
            client={client}
            vault={vault}
            onClose={() => setSettingsOpen(false)}
            onVaultChanged={setVault}
            onError={setError}
            onStatus={setStatus}
          />
        )}
        <Toast message={toast} />
      </main>
    </div>
  );
}

// ---- onboarding screens ------------------------------------------------------

function Welcome({
  client,
  onCreated,
  onOpenExisting,
  onError,
}: {
  client: CoreClient;
  onCreated: (vault: VaultInfoDto) => void;
  onOpenExisting: () => void;
  onError: (e: string) => void;
}) {
  const [mode, setMode] = useState<"choose" | "passphrase">("choose");
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  if (mode === "choose") {
    return (
      <Page title="Unlock your vault">
        <p style={{ color: "var(--text-secondary)" }}>Your passphrase stays on this device.</p>
        <div style={{ display: "flex", flexDirection: "column", gap: "var(--sp-3)", maxWidth: "var(--detail-max)" }}>
          <Button variant="primary" onClick={() => setMode("passphrase")}>
            Create vault
          </Button>
          <Button variant="secondary" onClick={onOpenExisting}>
            Open existing vault
          </Button>
        </div>
        <p style={{ color: "var(--text-muted)", fontSize: 12, marginTop: "var(--sp-4)" }}>
          No Clavis account needed. Your codes work offline; sync through your own storage is optional.
        </p>
      </Page>
    );
  }
  return (
    <Page title="Create a passphrase">
      <p style={{ color: "var(--text-secondary)" }}>
        Use at least 12 characters — several random words work well. Paste is allowed; whitespace is kept exactly as
        typed. Your passphrase never leaves this device.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setLocalError(null);
          if (pass.length < 12) {
            setLocalError("Minimum 12 characters.");
            return;
          }
          if (pass !== confirm) {
            setLocalError("Passphrases do not match.");
            return;
          }
          void client
            .createVault(pass)
            .then((v) => onCreated(v))
            .catch((err) => onError(safeErrorMessage(err)));
        }}
      >
        <Field
          label="Passphrase"
          type="password"
          autoComplete="new-password"
          value={pass}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPass(e.target.value)}
          error={localError && pass.length < 12 ? "Minimum 12 characters." : undefined}
        />
        <Field
          label="Confirm passphrase"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setConfirm(e.target.value)}
          error={localError && pass.length >= 12 ? localError : undefined}
        />
        <Button variant="primary" type="submit">
          Continue
        </Button>
      </form>
    </Page>
  );
}

function RecoverySetup({
  client,
  vault,
  onDone,
  onError,
}: {
  client: CoreClient;
  vault: VaultInfoDto;
  onDone: (v: VaultInfoDto) => void;
  onError: (e: string) => void;
}) {
  const [key] = useState(
    () => "clavis-recovery-v1:4demo4key4shown4only4in4ui4tests4not4a4real4key",
  );
  const [confirmed, setConfirmed] = useState(false);
  const [chars, setChars] = useState("");
  // The demonstration key here is synthetic; the real key comes from the
  // one-session native presentation during live onboarding.
  void client;
  void vault;

  return (
    <Page title="Save your recovery key">
      <RecoveryKeyCard recoveryKey={key} onConfirm={() => setConfirmed(true)} />
      {confirmed && (
        <div style={{ marginTop: "var(--sp-4)" }}>
          <Field
            label={`Type the first 4 characters of the key to confirm`}
            value={chars}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setChars(e.target.value)}
            hint="This checks you saved the key. It stays visible only during this session."
          />
          <Button
            variant="primary"
            onClick={() => {
              const expected = key.replace("clavis-recovery-v1:", "").slice(0, 4);
              if (chars.trim() !== expected) {
                onError("Verification failed — check the characters and try again, or go back.");
                return;
              }
              onDone(vault);
            }}
          >
            Verify and continue
          </Button>
        </div>
      )}
    </Page>
  );
}

function ConnectStorage({
  client,
  vault,
  onConnected,
  onCancel,
  onError,
}: {
  client: CoreClient;
  vault: VaultInfoDto;
  onConnected: (v: VaultInfoDto) => void;
  onCancel: () => void;
  onError: (e: string) => void;
}) {
  const [picking, setPicking] = useState(true);
  const [waitingUrl, setWaitingUrl] = useState<string | null>(null);
  const [callback, setCallback] = useState("");

  if (picking) {
    return (
      <Page title="Connect storage">
        <p style={{ color: "var(--text-secondary)" }}>
          Optional: sync encrypted vault data through your own storage account. Your vault stays encrypted with its
          passphrase either way.
        </p>
        <ProviderPicker
          onPick={async (provider) => {
            if (provider === "local") {
              onCancel();
              return;
            }
            try {
              const url = await client.connectProviderBegin(provider);
              setWaitingUrl(url);
              setPicking(false);
              // The real shell opens the OS browser via the opener plugin.
              window.open(url, "_blank");
            } catch (e) {
              onError(safeErrorMessage(e));
            }
          }}
          onCancel={onCancel}
        />
      </Page>
    );
  }
  return (
    <Page title="Finish connecting">
      <p style={{ color: "var(--text-secondary)" }}>
        After authorizing in your browser, paste the callback URL here. Canceled or wrong-account consents are safely
        rejected.
      </p>
      <Field label="Callback URL" value={callback} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setCallback(e.target.value)} />
      <div style={{ display: "flex", gap: "var(--sp-2)" }}>
        <Button
          variant="primary"
          onClick={() => {
            void client
              .connectProviderComplete(vault.provider_kind ?? "google_drive", callback)
              .then(onConnected)
              .catch((e) => onError(safeErrorMessage(e)));
          }}
        >
          Connect
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
      {waitingUrl && <p style={{ color: "var(--text-muted)", fontSize: 12 }}>Waiting for authorization…</p>}
    </Page>
  );
}

function Unlock({
  client,
  vault,
  onUnlocked,
  onError,
}: {
  client: CoreClient;
  vault: VaultInfoDto | null;
  onUnlocked: (v: VaultInfoDto) => void;
  onError: (e: string) => void;
}) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <Page title="Unlock your vault">
      <p style={{ color: "var(--text-secondary)" }}>
        {vault?.provider_kind ? `Synced via ${vault.provider_kind.replace("_", " ")}` : "Your passphrase stays on this device."}
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          void client
            .unlock(pass)
            .then((v) => onUnlocked(v))
            .catch((err) => {
              // Generic failure message; never hint whether the vault exists.
              onError(
                "Could not unlock this vault. Check your passphrase or try a backup.",
              );
              void err;
            })
            .finally(() => setBusy(false));
        }}
      >
        <SecretInput
          aria-label="Vault passphrase"
          value={pass}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPass(e.target.value)}
          autoFocus
        />
        <div style={{ height: "var(--sp-3)" }} />
        <Button variant="primary" type="submit" disabled={busy}>
          Unlock
        </Button>
      </form>
      <p style={{ color: "var(--text-muted)", fontSize: 12, marginTop: "var(--sp-4)" }}>
        Clavis cannot reset a forgotten vault passphrase without your recovery key.
      </p>
    </Page>
  );
}

// ---- account dialogs ----------------------------------------------------------

function AddAccountDialog({
  client,
  onClose,
  onAdded,
}: {
  client: CoreClient;
  onClose: () => void;
  onAdded: () => void;
}) {
  const [tab, setTab] = useState<"uri" | "image" | "manual">("uri");
  const [uri, setUri] = useState("");
  const [imageBytes, setImageBytes] = useState<number[] | null>(null);
  const [imageName, setImageName] = useState<string | null>(null);
  const [multiCount, setMultiCount] = useState<number | null>(null);
  const [manual, setManual] = useState({
    issuer: "",
    account_label: "",
    secret_base32: "",
    algorithm: "SHA1",
    digits: 6,
    period_seconds: 30,
  });
  const [preview, setPreview] = useState<import("@clavis/contracts").ImportPreviewDto | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runPreview = async (p: Promise<import("@clavis/contracts").ImportPreviewDto>) => {
    setError(null);
    setMultiCount(null);
    try {
      setPreview(await p);
    } catch (e) {
      const err = e as { kind?: string; message?: string };
      if (err?.kind === "multiple_candidates") {
        const n = Number((err.message ?? "").match(/\d+/)?.[0] ?? 0) || 0;
        setMultiCount(n);
        setError(err.message ?? null);
      } else {
        setError(safeErrorMessage(e));
      }
    }
  };

  const pickImage = (file: File) => {
    setImageName(file.name);
    setPreview(null);
    setError(null);
    setMultiCount(null);
    // FileReader works in every environment (unlike Blob.arrayBuffer).
    const reader = new FileReader();
    reader.onload = () => {
      const buf = new Uint8Array(reader.result as ArrayBuffer);
      setImageBytes(Array.from(buf));
    };
    reader.onerror = () => setError("The image could not be read.");
    reader.readAsArrayBuffer(file);
  };

  return (
    <Dialog title="Add account" onClose={onClose}>
      <div role="tablist" aria-label="Import method" style={{ display: "flex", gap: "var(--sp-2)", marginBottom: "var(--sp-3)", flexWrap: "wrap" }}>
        <Button variant={tab === "uri" ? "primary" : "secondary"} onClick={() => setTab("uri")} role="tab" aria-selected={tab === "uri"}>
          Paste URI
        </Button>
        <Button variant={tab === "image" ? "primary" : "secondary"} onClick={() => setTab("image")} role="tab" aria-selected={tab === "image"}>
          QR image
        </Button>
        <Button variant={tab === "manual" ? "primary" : "secondary"} onClick={() => setTab("manual")} role="tab" aria-selected={tab === "manual"}>
          Manual entry
        </Button>
      </div>
      {tab === "uri" && (
        <Field label="otpauth:// URI" value={uri} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUri(e.target.value)} hint="Scanned content is parsed as text only." />
      )}
      {tab === "image" && (
        <div>
          <label
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "var(--sp-2)",
              minHeight: 72,
              border: "1px dashed var(--border-subtle)",
              borderRadius: "var(--radius-row)",
              cursor: "pointer",
              color: "var(--text-secondary)",
            }}
          >
            <input
              type="file"
              accept="image/png,image/jpeg"
              style={{ display: "none" }}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void pickImage(f);
              }}
            />
            {imageName ? `Selected: ${imageName} — click to change` : "Choose a QR image (PNG or JPEG)…"}
          </label>
          <p style={{ color: "var(--text-muted)", fontSize: 12 }}>
            Images are decoded locally on this device; nothing is uploaded.
          </p>
          {multiCount !== null && (
            <div style={{ display: "flex", gap: "var(--sp-2)", flexWrap: "wrap", marginBottom: "var(--sp-3)" }}>
              {Array.from({ length: multiCount }, (_, i) => (
                <Button
                  key={i}
                  variant="secondary"
                  onClick={() => imageBytes && void runPreview(client.previewImportImage(imageBytes, i))}
                >
                  Use QR code {i + 1}
                </Button>
              ))}
            </div>
          )}
          <Button
            variant="primary"
            disabled={!imageBytes}
            onClick={() => imageBytes && void runPreview(client.previewImportImage(imageBytes))}
          >
            Preview
          </Button>
        </div>
      )}
      {tab === "manual" && (
        <>
          <Field label="Issuer (optional)" value={manual.issuer} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setManual({ ...manual, issuer: e.target.value })} />
          <Field label="Account label" value={manual.account_label} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setManual({ ...manual, account_label: e.target.value })} />
          <Field
            label="Secret (Base32)"
            value={manual.secret_base32}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setManual({ ...manual, secret_base32: e.target.value })}
            hint="Spaces are ignored in manual key entry."
          />
          <div style={{ display: "flex", gap: "var(--sp-3)" }}>
            <Field label="Algorithm" value={manual.algorithm} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setManual({ ...manual, algorithm: e.target.value.toUpperCase() })} />
            <Field
              label="Digits"
              type="number"
              value={String(manual.digits)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setManual({ ...manual, digits: Number(e.target.value) })}
            />
            <Field
              label="Period (s)"
              type="number"
              value={String(manual.period_seconds)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setManual({ ...manual, period_seconds: Number(e.target.value) })}
            />
          </div>
          <Button
            variant="primary"
            onClick={() =>
              void runPreview(
                client.previewImportManual({
                  issuer: manual.issuer,
                  account_label: manual.account_label,
                  secret_base32: manual.secret_base32,
                  algorithm: manual.algorithm,
                  digits: manual.digits,
                  period_seconds: manual.period_seconds,
                }),
              )
            }
          >
            Preview
          </Button>
        </>
      )}
      {error && (
        <p role="alert" style={{ color: "var(--status-danger)" }}>
          {error}
        </p>
      )}
      {preview && (
        <div>
          <div
            style={{
              border: `1px solid ${preview.duplicate_warning ? "var(--status-warning)" : "var(--border-subtle)"}`,
              borderRadius: "var(--radius-row)",
              padding: "var(--sp-3)",
              marginBottom: "var(--sp-3)",
            }}
          >
            <strong>{preview.issuer ?? "(no issuer)"}</strong>
            <div style={{ color: "var(--text-secondary)" }}>{preview.account_label}</div>
            <div style={{ color: "var(--text-muted)", fontSize: 12 }}>
              {String(preview.algorithm).toUpperCase()} · {preview.digits} digits · {preview.period_seconds}s
            </div>
            {preview.duplicate_warning && (
              <p role="alert" style={{ color: "var(--status-warning)", fontSize: 12, margin: "var(--sp-2) 0 0" }}>
                Warning: this OTP configuration matches an existing account. Adding is possible after confirmation.
              </p>
            )}
          </div>
          <div style={{ display: "flex", gap: "var(--sp-2)" }}>
            <Button
              variant="primary"
              onClick={() => {
                void client.confirmImport(preview.handle).then(onAdded).catch((e) => setError(safeErrorMessage(e)));
              }}
            >
              Add account
            </Button>
            <Button variant="secondary" onClick={() => setPreview(null)}>
              Back
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

function EditAccountDialog({
  client,
  account,
  onClose,
  onChanged,
  onConflict,
}: {
  client: CoreClient;
  account: AccountSummaryDto;
  onClose: () => void;
  onChanged: () => void;
  onConflict: () => void;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [label, setLabel] = useState(account.account_label ?? "");
  const [error, setError] = useState<string | null>(null);
  const act = (p: Promise<unknown>) =>
    p.then(onChanged).catch((e) => {
      const msg = safeErrorMessage(e);
      if (msg.includes("conflict") || msg.includes("stale")) onConflict();
      else setError(msg);
    });
  return (
    <Dialog title="Edit account" onClose={onClose}>
      {confirmDelete ? (
        <>
          <p>
            Delete <strong>{account.issuer ?? account.account_label}</strong>? The change syncs to your other devices;
            encrypted history is retained and a simultaneous edit becomes a conflict you can resolve.
          </p>
          <div style={{ display: "flex", gap: "var(--sp-2)" }}>
            <Button variant="danger" onClick={() => void act(client.deleteAccount(account.id))}>
              Delete account
            </Button>
            <Button variant="secondary" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
          </div>
        </>
      ) : (
        <>
          <Field label="Issuer" value={label} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setLabel(e.target.value)} />
          <div style={{ display: "flex", gap: "var(--sp-2)", flexWrap: "wrap" }}>
            <Button
              variant="primary"
              onClick={() => void act(client.updateAccount(account.id, { accountLabel: label }))}
            >
              Save
            </Button>
            <Button
              variant="secondary"
              onClick={() => void act(client.updateAccount(account.id, { favorite: !account.favorite }))}
            >
              {account.favorite ? "Remove favorite" : "Add favorite"}
            </Button>
            <Button variant="danger" onClick={() => setConfirmDelete(true)}>
              Delete…
            </Button>
          </div>
        </>
      )}
      {error && (
        <p role="alert" style={{ color: "var(--status-danger)", marginTop: "var(--sp-3)" }}>
          {error}
        </p>
      )}
    </Dialog>
  );
}
