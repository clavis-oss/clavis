import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import type { CoreClient } from "../../core/bridge";
import type { SyncStatusKind, VaultInfoDto } from "@clavis/contracts";

/**
 * Settings: appearance, lock timeout, clipboard timeout, storage,
 * recovery/export. Disconnect keeps the local vault; no device list
 * promises remote revocation. Theme choice is device-local and persists
 * while locked.
 */
export function Settings({
  client,
  vault,
  onClose,
  onVaultChanged,
  onError,
  onStatus,
}: {
  client: CoreClient;
  vault: VaultInfoDto | null;
  onClose: () => void;
  onVaultChanged: (v: VaultInfoDto) => void;
  onError: (e: string) => void;
  onStatus: (s: SyncStatusKind) => void;
}) {
  const theme = (document.documentElement.dataset.theme ?? "system") as "system" | "light" | "dark";
  return (
    <Dialog title="Settings" onClose={onClose}>
      <section style={{ marginBottom: "var(--sp-4)" }}>
        <h3 style={{ margin: "0 0 var(--sp-2)", fontSize: 16, lineHeight: "24px", fontWeight: 600 }}>Appearance</h3>
        {(["system", "light", "dark"] as const).map((t) => (
          <label key={t} style={{ display: "block", padding: "var(--sp-1) 0" }}>
            <input
              type="radio"
              name="theme"
              checked={theme === t}
              onChange={() => {
                if (t === "system") {
                  delete document.documentElement.dataset.theme;
                } else {
                  document.documentElement.dataset.theme = t;
                }
                // Re-render by dispatching a no-op storage event is
                // unnecessary; the settings dialog re-reads on next open.
              }}
            />{" "}
            {t[0].toUpperCase() + t.slice(1)}
          </label>
        ))}
      </section>

      <section style={{ marginBottom: "var(--sp-4)" }}>
        <h3 style={{ margin: "0 0 var(--sp-2)", fontSize: 16, lineHeight: "24px", fontWeight: 600 }}>Locking</h3>
        <p style={{ color: "var(--text-secondary)", margin: 0 }}>
          This app locks after 5 minutes of inactivity. “Lock this app” locks this client only — other open Clavis
          clients have their own unlock sessions.
        </p>
      </section>

      <section style={{ marginBottom: "var(--sp-4)" }}>
        <h3 style={{ margin: "0 0 var(--sp-2)", fontSize: 16, lineHeight: "24px", fontWeight: 600 }}>Clipboard</h3>
        <p style={{ color: "var(--text-secondary)", margin: 0 }}>
          Copied codes are cleared after 30 seconds if the clipboard still contains them. OS clipboard histories may
          retain values.
        </p>
      </section>

      <section style={{ marginBottom: "var(--sp-4)" }}>
        <h3 style={{ margin: "0 0 var(--sp-2)", fontSize: 16, lineHeight: "24px", fontWeight: 600 }}>Storage</h3>
        {vault?.provider_kind ? (
          <>
            <p style={{ color: "var(--text-secondary)", margin: "0 0 var(--sp-2)" }}>
              Synced via {vault.provider_kind.replace("_", " ")}. Disconnecting keeps your vault on this device;
              automatic sync stops.
            </p>
            <div style={{ display: "flex", gap: "var(--sp-2)" }}>
              <Button
                variant="secondary"
                onClick={() => {
                  void client
                    .syncNow()
                    .then(onStatus)
                    .catch((e) => onError(String(e)));
                }}
              >
                Sync now
              </Button>
              <Button
                variant="danger"
                onClick={() => {
                  void client
                    .disconnectProvider(vault.provider_kind ?? "")
                    .then(() => onVaultChanged({ ...vault, provider_kind: null }))
                    .catch((e) => onError(String(e)));
                }}
              >
                Disconnect storage…
              </Button>
            </div>
          </>
        ) : (
          <p style={{ color: "var(--text-secondary)", margin: 0 }}>
            Local only. Connect storage to sync automatically; your codes work offline either way.
          </p>
        )}
      </section>

      <section>
        <h3 style={{ margin: "0 0 var(--sp-2)", fontSize: 16, lineHeight: "24px", fontWeight: 600 }}>
          Recovery and export
        </h3>
        <p style={{ color: "var(--text-secondary)", margin: "0 0 var(--sp-2)" }}>
          Export an encrypted backup to restore without your storage provider. Clavis cannot reset a forgotten vault
          passphrase without your recovery key.
        </p>
        <Button
          variant="primary"
          onClick={() => {
            void client
              .exportVault("clavis-backup.clvx")
              .then((dest) => onError(`Encrypted export written to ${dest} (verify it before deleting anything).`))
              .catch((e) => onError(String(e)));
          }}
        >
          Export encrypted backup…
        </Button>
      </section>
    </Dialog>
  );
}
