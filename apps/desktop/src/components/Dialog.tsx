import { useEffect, type ReactNode } from "react";

/**
 * Accessible dialog: traps focus, closes on Escape and restores focus to
 * the opener on close. Max width 440 px (drawer/modal, never a third
 * column).
 */
export function Dialog({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
      if (e.key === "Tab") {
        // Simple focus trap across focusable descendants.
        const dialog = document.getElementById("clavis-dialog");
        if (!dialog) return;
        const focusables = dialog.querySelectorAll<HTMLElement>(
          "button, input, [tabindex]:not([tabindex='-1'])",
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    const panel = document.getElementById("clavis-dialog");
    panel?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      opener?.focus();
    };
  }, [onClose]);

  return (
    <div
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.4)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
    >
      <div
        id="clavis-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        style={{
          maxWidth: "var(--detail-max)",
          width: "100%",
          background: "var(--surface-panel)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-dialog)",
          padding: "var(--sp-5)",
          maxHeight: "85vh",
          overflow: "auto",
        }}
      >
        <h2 style={{ margin: "0 0 var(--sp-4)", fontSize: 16, lineHeight: "24px", fontWeight: 600 }}>
          {title}
        </h2>
        {children}
      </div>
    </div>
  );
}
