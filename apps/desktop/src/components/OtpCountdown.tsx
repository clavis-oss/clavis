import { useEffect, useRef, useState } from "react";

/**
 * Countdown from the actual code validity period. Below 5 seconds use the
 * warning color and text without flashing. Never announces every second to
 * screen readers: the wrapper is aria-hidden and the code is announced only
 * via explicit copy feedback.
 */
export function OtpCountdown({
  validUntilUnixMs,
  periodSeconds,
  onRollover,
}: {
  validUntilUnixMs: string;
  periodSeconds?: number;
  onRollover?: () => void;
}) {
  const validUntil = Number(validUntilUnixMs);
  const [remaining, setRemaining] = useState(() =>
    Math.max(0, Math.ceil((validUntil - Date.now()) / 1000)),
  );
  const rolloverRef = useRef(onRollover);
  rolloverRef.current = onRollover;

  useEffect(() => {
    const tick = () => {
      const next = Math.max(0, Math.ceil((validUntil - Date.now()) / 1000));
      setRemaining((prev) => {
        if (prev > 0 && next === 0) {
          rolloverRef.current?.();
        }
        return next;
      });
    };
    tick();
    const t = setInterval(tick, 250);
    return () => clearInterval(t);
  }, [validUntil]);

  const expiring = remaining < 5;
  const fraction = periodSeconds ? remaining / periodSeconds : remaining / 30;
  return (
    <div aria-hidden="true" style={{ display: "flex", alignItems: "center", gap: "var(--sp-2)" }}>
      <svg width="16" height="16" viewBox="0 0 16 16">
        <circle cx="8" cy="8" r="6.5" fill="none" stroke="var(--border-subtle)" strokeWidth="2" />
        <circle
          cx="8"
          cy="8"
          r="6.5"
          fill="none"
          stroke={expiring ? "var(--status-warning)" : "var(--accent-primary)"}
          strokeWidth="2"
          strokeDasharray={`${Math.max(0, Math.min(1, fraction)) * 40.8} 40.8`}
          transform="rotate(-90 8 8)"
        />
      </svg>
      <span
        style={{
          color: expiring ? "var(--status-warning)" : "var(--text-muted)",
          fontSize: 12,
          lineHeight: "18px",
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {remaining}s
      </span>
    </div>
  );
}
