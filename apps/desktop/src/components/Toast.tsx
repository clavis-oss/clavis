import { useEffect, useState } from "react";

/** "Code copied" — no OTP digits, no account label; 3 s, announced once. */
export function Toast({ message }: { message: string | null }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    if (!message) return;
    setVisible(true);
    const t = setTimeout(() => setVisible(false), 3000);
    return () => clearTimeout(t);
  }, [message]);
  if (!message || !visible) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        position: "fixed",
        bottom: "var(--sp-5)",
        left: "50%",
        transform: "translateX(-50%)",
        background: "var(--surface-panel)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "var(--radius-dialog)",
        padding: "var(--sp-2) var(--sp-4)",
        zIndex: 200,
        transition: "opacity var(--transition)",
      }}
    >
      {message}
    </div>
  );
}
