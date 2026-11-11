import { useState, type ReactNode } from "react";

import { Button } from "./Button";

/** Empty state: local-first explanation without technical jargon. */
export function EmptyState({ onAdd, searchEmpty }: { onAdd: () => void; searchEmpty?: boolean }) {
  return (
    <div
      style={{
        minHeight: 240,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: "var(--sp-4)",
        color: "var(--text-secondary)",
        textAlign: "center",
      }}
    >
      <h2 style={{ margin: 0, fontSize: 16, lineHeight: "24px", fontWeight: 600, color: "var(--text-primary)" }}>
        {searchEmpty ? "No accounts match your search." : "Your codes, wherever you need them."}
      </h2>
      {!searchEmpty && (
        <>
          <p style={{ margin: 0, maxWidth: 360 }}>
            Clavis keeps your login codes on this device and syncs them — encrypted — through storage you choose. Your
            codes work even when you are offline.
          </p>
          <Button variant="primary" onClick={onAdd}>
            Add account
          </Button>
        </>
      )}
    </div>
  );
}

/** Provider picker: sample cards use initials, never unlicensed brand art. */
export function ProviderPicker({
  onPick,
  onCancel,
}: {
  onPick: (provider: "google_drive" | "onedrive" | "dropbox" | "local") => void;
  onCancel: () => void;
}) {
  const cards: { id: "google_drive" | "onedrive" | "dropbox" | "local"; initial: string; name: string; note: string }[] = [
    { id: "google_drive", initial: "G", name: "Google Drive", note: "App-created files only" },
    { id: "onedrive", initial: "O", name: "OneDrive", note: "App folder only" },
    { id: "dropbox", initial: "D", name: "Dropbox", note: "App folder only" },
    { id: "local", initial: "L", name: "Use locally", note: "No automatic sync; export backups yourself" },
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--sp-3)", maxWidth: "var(--detail-max)" }}>
      {cards.map((c) => (
        <button
          key={c.id}
          onClick={() => onPick(c.id)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "var(--sp-3)",
            minHeight: "var(--control-min)",
            padding: "var(--sp-3)",
            textAlign: "left",
            background: "var(--surface-panel)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "var(--radius-row)",
            cursor: "pointer",
          }}
        >
          <span
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
            }}
          >
            {c.initial}
          </span>
          <span>
            <span style={{ display: "block", fontWeight: 600 }}>{c.name}</span>
            <span style={{ color: "var(--text-muted)", fontSize: 12 }}>{c.note}</span>
          </span>
        </button>
      ))}
      <Button variant="secondary" onClick={onCancel}>
        Cancel
      </Button>
    </div>
  );
}

/**
 * Masked secret input: explicit reveal, paste allowed, no spellcheck,
 * autocorrect or autocomplete; no global form analytics.
 */
export function SecretInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const [reveal, setReveal] = useState(false);
  return (
    <div style={{ display: "flex", gap: "var(--sp-2)", alignItems: "stretch" }}>
      <input
        type={reveal ? "text" : "password"}
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        autoComplete="off"
        {...props}
        style={{
          flex: 1,
          minHeight: "var(--control-min)",
          padding: "0 var(--sp-3)",
          borderRadius: "var(--radius-control)",
          border: "1px solid var(--border-subtle)",
          background: "var(--surface-canvas)",
          ...props.style,
        }}
      />
      <button
        type="button"
        onClick={() => setReveal((r) => !r)}
        aria-pressed={reveal}
        aria-label={reveal ? "Hide secret" : "Reveal secret"}
        style={{
          minWidth: 36,
          minHeight: 36,
          borderRadius: "var(--radius-control)",
          border: "1px solid var(--border-subtle)",
          background: "transparent",
          cursor: "pointer",
        }}
      >
        {reveal ? "🙈" : "👁"}
      </button>
    </div>
  );
}

/**
 * Grouped recovery-key presentation. The canonical bytes never change;
 * show/copy only within initial/recovery setup.
 */
export function RecoveryKeyCard({ recoveryKey, onConfirm }: { recoveryKey: string; onConfirm: () => void }) {
  const groups = recoveryKey.replace("clavis-recovery-v1:", "").match(/.{1,8}/g) ?? [];
  return (
    <div>
      <p style={{ color: "var(--status-warning)", fontWeight: 600 }}>
        Keep this key somewhere safe, separate from your encrypted backup. Anyone with both can unlock the backup.
      </p>
      <div
        className="otp-code"
        style={{
          fontSize: 16,
          lineHeight: "26px",
          background: "var(--surface-panel)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-row)",
          padding: "var(--sp-4)",
          wordBreak: "break-all",
          userSelect: "all",
        }}
      >
        {groups.map((g, i) => (
          <span key={i} style={{ marginRight: "var(--sp-2)" }}>
            {g}
          </span>
        ))}
      </div>
      <p style={{ color: "var(--text-muted)", fontSize: 12 }}>
        Clavis cannot reset a forgotten vault passphrase without your recovery key. This key is shown only once.
      </p>
      <Button variant="primary" onClick={onConfirm}>
        I saved my recovery key
      </Button>
    </div>
  );
}

export function SearchField({
  value,
  onChange,
  inputRef,
}: {
  value: string;
  onChange: (v: string) => void;
  inputRef?: React.RefObject<HTMLInputElement | null>;
}) {
  return (
    <input
      ref={inputRef}
      type="search"
      aria-label="Search accounts"
      placeholder="Search accounts"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === "Escape") onChange("");
      }}
      style={{
        minHeight: "var(--control-min)",
        flex: 1,
        minWidth: 160,
        maxWidth: 420,
        padding: "0 var(--sp-3)",
        borderRadius: "var(--radius-control)",
        border: "1px solid var(--border-subtle)",
        background: "var(--surface-canvas)",
      }}
    />
  );
}

export function Page({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <div style={{ padding: "var(--sp-5)", maxWidth: 720, margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "var(--sp-4)" }}>
        <h1 style={{ margin: 0, fontSize: 24, lineHeight: "30px", fontWeight: 600 }}>{title}</h1>
        {actions}
      </div>
      {children}
    </div>
  );
}
