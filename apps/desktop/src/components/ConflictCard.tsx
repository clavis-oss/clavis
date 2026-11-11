import type { ConflictDetailDto } from "@clavis/contracts";

import { Button } from "./Button";
import { Dialog } from "./Dialog";

/**
 * Conflict resolution: compare candidates; secret candidates show origin and
 * parameters with masked content — never a seed. "Keep both accounts" is
 * offered when meaningful.
 */
export function ConflictCard({
  conflict,
  accountName,
  onKeep,
  onKeepBoth,
  onCancel,
}: {
  conflict: ConflictDetailDto;
  accountName: string;
  onKeep: (candidateIndex: number) => void;
  onKeepBoth?: (keepOriginal: number, keepNew: number) => void;
  onCancel: () => void;
}) {
  return (
    <Dialog title="Two devices changed this account. Choose which change to keep." onClose={onCancel}>
      <p style={{ color: "var(--text-secondary)" }}>
        {accountName} · field: <strong>{conflict.field.replace("_", " ")}</strong>
      </p>
      <div role="radiogroup" aria-label="Competing changes" style={{ display: "flex", flexDirection: "column", gap: "var(--sp-2)" }}>
        {conflict.candidates.map((c) => (
          <label
            key={c.index}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "var(--sp-3)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "var(--radius-row)",
              padding: "var(--sp-3)",
              cursor: "pointer",
            }}
          >
            <input type="radio" name={`candidate-${conflict.entry_id}`} value={c.index} onChange={() => onKeep(c.index)} />
            <span style={{ flex: 1 }}>
              <span style={{ display: "block" }}>{c.display}</span>
              <span style={{ color: "var(--text-muted)", fontSize: 12 }}>from device {c.origin.slice(0, 8)}</span>
            </span>
          </label>
        ))}
      </div>
      <div style={{ display: "flex", gap: "var(--sp-2)", marginTop: "var(--sp-4)" }}>
        {onKeepBoth && conflict.candidates.length === 2 && (
          <Button variant="secondary" onClick={() => onKeepBoth(0, 1)}>
            Keep both accounts
          </Button>
        )}
        <Button variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
      <p style={{ color: "var(--text-muted)", fontSize: 12 }}>
        Your choice syncs to your other devices. Codes for this account stay hidden until the conflict is resolved.
      </p>
    </Dialog>
  );
}
