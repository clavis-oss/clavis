import { useId, type InputHTMLAttributes } from "react";

/** Labeled field; errors are associated with the input via aria-describedby. */
export function Field({
  label,
  error,
  hint,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: string; error?: string; hint?: string }) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--sp-1)", marginBottom: "var(--sp-3)" }}>
      <label htmlFor={id} style={{ color: "var(--text-secondary)", fontSize: 12, lineHeight: "18px" }}>
        {label}
      </label>
      <input
        id={id}
        aria-describedby={[hint ? hintId : null, error ? errId : null].filter(Boolean).join(" ") || undefined}
        aria-invalid={error ? true : undefined}
        style={{
          minHeight: "var(--control-min)",
          padding: "0 var(--sp-3)",
          borderRadius: "var(--radius-control)",
          border: `1px solid ${error ? "var(--status-danger)" : "var(--border-subtle)"}`,
          background: "var(--surface-canvas)",
        }}
        {...rest}
      />
      {hint && (
        <span id={hintId} style={{ color: "var(--text-muted)", fontSize: 12, lineHeight: "18px" }}>
          {hint}
        </span>
      )}
      {error && (
        <span id={errId} role="alert" style={{ color: "var(--status-danger)", fontSize: 12, lineHeight: "18px" }}>
          {error}
        </span>
      )}
    </div>
  );
}
