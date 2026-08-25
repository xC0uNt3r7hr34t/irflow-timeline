import useTheme from "../../hooks/useTheme.js";

/**
 * Inline error display for failed modal/fetch operations.
 *
 * Replaces the blank-modal pattern that resulted from `.catch(() => {})`
 * silently swallowing IPC errors. Used inside any modal body where a backend
 * analysis call may fail (malformed file, IPC crash, missing data).
 *
 * Props:
 *   message  : error text to display (required)
 *   onRetry  : optional handler — when provided, renders a Retry button
 *   compact  : if true, renders a tighter inline variant (e.g. inside a card row)
 */
export default function ErrorState({ message, onRetry, compact = false }) {
  const { th } = useTheme();
  const padding = compact ? "8px 12px" : "20px 24px";
  const iconSize = compact ? 14 : 20;
  const fontSize = compact ? 11 : 12;

  return (
    <div role="alert" style={{
      display: "flex", alignItems: "flex-start", gap: 10, padding,
      background: `${th.danger}12`, border: `1px solid ${th.danger}44`, borderRadius: 8,
      color: th.text, fontSize, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
      lineHeight: 1.45,
    }}>
      <svg width={iconSize} height={iconSize} viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: 1 }}>
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: th.danger, fontWeight: 600, marginBottom: compact ? 0 : 4 }}>
          Operation failed
        </div>
        <div style={{ color: th.textDim, wordBreak: "break-word" }}>{message}</div>
      </div>
      {onRetry && (
        <button onClick={onRetry} style={{
          padding: "4px 10px", background: `${th.danger}18`, color: th.danger,
          border: `1px solid ${th.danger}55`, borderRadius: 6, fontSize: 11, fontWeight: 600,
          cursor: "pointer", fontFamily: "inherit", flexShrink: 0,
          transition: "background var(--m-base) var(--ease-out)",
        }}>Retry</button>
      )}
    </div>
  );
}
