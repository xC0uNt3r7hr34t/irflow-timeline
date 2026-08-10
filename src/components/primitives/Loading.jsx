import useTheme from "../../hooks/useTheme.js";

/**
 * Themed inline loading indicator. Replaces ad-hoc plain "Loading..." text
 * scattered across modal bodies, the histogram, the filter dropdown, etc.
 *
 * Each existing site previously rolled its own (or skipped the spinner
 * entirely). This primitive uses the existing `tle-spin` keyframe so it stays
 * consistent with the larger full-page overlays.
 *
 * Variants:
 *   inline  : centered, ~40px square, spinner + label
 *   compact : single-line, small spinner inline with text — for status bars,
 *             toolbar slots, etc.
 *
 * Sizes (inline only): "sm" (default) | "md" | "lg"
 */
export default function Loading({
  label = "Loading…",
  variant = "inline",
  size = "sm",
  color,
}) {
  const { th } = useTheme();
  const tone = color || th.accent;

  if (variant === "compact") {
    return (
      <span style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        color: th.textDim, fontSize: 11, fontFamily: "-apple-system, sans-serif",
      }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={tone} strokeWidth="2.5"
          style={{ animation: "tle-spin 0.8s linear infinite", flexShrink: 0 }}>
          <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
        </svg>
        {label}
      </span>
    );
  }

  const sz = size === "lg" ? 24 : size === "md" ? 18 : 14;
  return (
    <div role="status" aria-live="polite" style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      gap: 8, padding: "20px 12px",
    }}>
      <svg width={sz} height={sz} viewBox="0 0 24 24" fill="none" stroke={tone} strokeWidth="2.5"
        style={{ animation: "tle-spin 0.8s linear infinite" }}>
        <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
      </svg>
      <span style={{
        color: th.textMuted, fontSize: 11,
        fontFamily: "-apple-system, sans-serif",
      }}>{label}</span>
    </div>
  );
}
