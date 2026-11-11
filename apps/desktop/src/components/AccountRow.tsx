import type { AccountSummaryDto, SyncStatusKind } from "@clavis/contracts";

/** Exact functional copy from document 02. */
export const statusCopy: Record<SyncStatusKind, string> = {
  local_only: "Local only",
  locked: "Sync resumes when you unlock this app",
  synced: "Synced",
  pending: "Saved on this device · waiting to sync",
  syncing: "Syncing…",
  offline: "Offline · your saved codes still work",
  reauth_required: "Reconnect your storage account. Your saved codes are available offline.",
  conflict: "Two devices changed this account. Choose which change to keep.",
  storage_full: "Storage full",
  integrity_error: "A synced revision failed validation",
  migration_required: "Changes on an old vault need importing",
};

function statusColor(kind: SyncStatusKind): string {
  switch (kind) {
    case "synced":
      return "var(--status-success)";
    case "pending":
    case "offline":
    case "reauth_required":
    case "locked":
      return "var(--status-warning)";
    case "conflict":
    case "storage_full":
    case "integrity_error":
    case "migration_required":
      return "var(--status-danger)";
    default:
      return "var(--text-muted)";
  }
}

/** Icon + text + provider kind; a spinning icon alone is never enough. */
export function SyncStatus({ status, providerKind }: { status: SyncStatusKind; providerKind?: string | null }) {
  return (
    <div
      aria-live="polite"
      style={{
        display: "flex",
        alignItems: "center",
        gap: "var(--sp-2)",
        color: statusColor(status),
        fontSize: 12,
        lineHeight: "18px",
      }}
    >
      <span aria-hidden="true">●</span>
      <span>{statusCopy[status]}</span>
      {providerKind && <span style={{ color: "var(--text-muted)" }}>· {providerKind.replace("_", " ")}</span>}
    </div>
  );
}

/** 88 px account row with a generic issuer tile and grouped OTP display. */
export function AccountRow({
  account,
  code,
  remainingSeconds,
  copied,
  onCopy,
  onEdit,
  onFavorite,
  onDelete,
}: {
  account: AccountSummaryDto;
  code?: string;
  remainingSeconds?: number;
  copied?: boolean;
  onCopy: () => void;
  onEdit: () => void;
  onFavorite: () => void;
  onDelete: () => void;
}) {
  const grouped = code ? groupCode(code) : "······";
  const expiring = remainingSeconds !== undefined && remainingSeconds < 5;
  return (
    <div
      style={{
        minHeight: 88,
        display: "flex",
        alignItems: "center",
        gap: "var(--sp-4)",
        background: "var(--surface-panel)",
        border: `1px solid ${account.has_conflict ? "var(--status-warning)" : "var(--border-subtle)"}`,
        borderRadius: "var(--radius-row)",
        padding: "0 var(--sp-4)",
      }}
    >
      {/* Generic 40 px issuer tile — bundled initials, no remote favicons. */}
      <div
        aria-hidden="true"
        style={{
          width: 40,
          height: 40,
          borderRadius: "var(--radius-control)",
          background: "var(--surface-hover)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 600,
          color: "var(--text-secondary)",
          flexShrink: 0,
        }}
      >
        {(account.issuer ?? account.account_label ?? "?").slice(0, 1).toUpperCase()}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600 }}>{account.issuer ?? account.account_label ?? "Unnamed account"}</div>
        <div style={{ color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis" }}>
          {account.issuer ? account.account_label : ""}
          {account.has_conflict && (
            <span style={{ color: "var(--status-warning)" }}> · conflict: choose which change to keep</span>
          )}
        </div>
      </div>
      <div style={{ textAlign: "right" }}>
        <div className="otp-code" style={expiring ? { color: "var(--status-warning)" } : undefined}>
          {grouped}
        </div>
        <div
          style={{
            color: expiring ? "var(--status-warning)" : "var(--text-muted)",
            fontSize: 12,
            lineHeight: "18px",
          }}
        >
          {remainingSeconds !== undefined ? `${remainingSeconds}s` : ""}
        </div>
      </div>
      <button
        onClick={onCopy}
        aria-label={copied ? "Copied" : `Copy code for ${account.issuer ?? "account"}`}
        style={{
          minHeight: 36,
          minWidth: 36,
          borderRadius: "var(--radius-control)",
          border: "1px solid var(--border-subtle)",
          background: "transparent",
          cursor: "pointer",
        }}
      >
        {copied ? "✓" : "⧉"}
      </button>
      <button
        onClick={onEdit}
        aria-label={`Edit ${account.issuer ?? "account"}`}
        style={{
          minHeight: 36,
          minWidth: 36,
          borderRadius: "var(--radius-control)",
          border: "1px solid var(--border-subtle)",
          background: "transparent",
          cursor: "pointer",
        }}
      >
        ⋯
      </button>
    </div>
  );
}

/** Group digits: `123 456` or `1234 5678`. */
export function groupCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
