import type { ButtonHTMLAttributes, CSSProperties, ReactNode } from "react";

type Variant = "primary" | "secondary" | "danger";

const styles: Record<Variant, CSSProperties> = {
  primary: {
    background: "var(--accent-primary)",
    color: "var(--accent-on-primary)",
    border: "1px solid var(--accent-primary)",
  },
  secondary: {
    background: "transparent",
    color: "var(--text-primary)",
    border: "1px solid var(--border-subtle)",
  },
  danger: {
    background: "transparent",
    color: "var(--status-danger)",
    border: "1px solid var(--status-danger)",
  },
};

export function Button({
  variant = "secondary",
  children,
  style,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; children: ReactNode }) {
  return (
    <button
      {...rest}
      style={{
        minHeight: "var(--control-min)",
        padding: "0 var(--sp-4)",
        borderRadius: "var(--radius-control)",
        cursor: rest.disabled ? "not-allowed" : "pointer",
        transition: "background var(--transition)",
        ...styles[variant],
        ...style,
      }}
    >
      {children}
    </button>
  );
}
