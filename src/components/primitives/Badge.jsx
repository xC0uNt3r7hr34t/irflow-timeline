import useTheme from "../../hooks/useTheme.js";

/**
 * Small colored pill / status label.
 *
 * Tones:
 *   UI states:    neutral (default) | accent | success | warning | danger
 *   Severity:     critical | high | med | low | custom | clean | info
 *                 (mapped through `th.sev.*` so light + dark variants apply)
 *
 * Variant: solid (filled) | soft (tinted bg + colored text + border, default)
 *
 * The severity tones replace ~3 inline impls across PersistenceModal /
 * LateralMovementModal / TimestompingModal / IocModal / ProcessTreeModal that
 * each defined their own SEVERITY_COLORS / sevColors / _pillColors maps.
 */
export default function Badge({
  tone = "neutral",
  variant = "soft",
  size = "md",
  style: extraStyle,
  children,
}) {
  const { th } = useTheme();

  const toneColor = (() => {
    switch (tone) {
      case "accent":   return th.accent;
      case "success":  return th.success;
      case "warning":  return th.warning;
      case "danger":   return th.danger;
      // Severity scale — sourced from th.sev.* so it adapts to light/dark.
      case "critical": return th.sev.critical;
      case "high":     return th.sev.high;
      case "med":
      case "medium":   return th.sev.med;
      case "low":      return th.sev.low;
      case "custom":   return th.sev.custom;
      case "clean":    return th.sev.clean;
      case "info":     return th.sev.info;
      case "neutral":
      default:
        return th.textDim;
    }
  })();

  // Foreground for solid variant: severity 'med' / 'clean' / 'info' / 'low' use
  // dark text instead of white, since their backgrounds are too light for white
  // text to pass WCAG AA at small sizes.
  const solidUsesDarkFg = ["med", "medium", "clean", "info", "low"].includes(tone);

  const sizeMap = {
    sm: { padding: "1px 5px", fontSize: 10 },
    md: { padding: "2px 7px", fontSize: 11 },
    lg: { padding: "3px 9px", fontSize: 12 },
  };
  const sz = sizeMap[size] || sizeMap.md;

  const isSolid = variant === "solid";
  return (
    <span
      style={{
        ...sz,
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        background: isSolid ? toneColor : toneColor + "22",
        color: isSolid ? (solidUsesDarkFg ? "#1c1917" : "#fff") : toneColor,
        border: isSolid ? "none" : `1px solid ${toneColor}44`,
        borderRadius: 4,
        fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
        fontWeight: 500,
        whiteSpace: "nowrap",
        lineHeight: 1.4,
        ...extraStyle,
      }}
    >
      {children}
    </span>
  );
}
