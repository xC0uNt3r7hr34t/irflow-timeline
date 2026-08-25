import { formatNumber } from "../utils/format.js";

const actionStyle = (th, tone = "normal") => ({
  background: tone === "accent" ? `${th.accent}1f` : th.btnBg,
  border: `1px solid ${tone === "accent" ? `${th.accent}66` : th.border}`,
  borderRadius: 5,
  color: tone === "accent" ? th.accent : th.textDim,
  cursor: "pointer",
  fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
  fontSize: 10,
  fontWeight: 600,
  padding: "3px 9px",
});

export default function SelectionBar({
  th,
  selectionCount,
  hiddenSelectionCount,
  allRowsSelected,
  onCopy,
  onBulkActions,
  onClear,
}) {
  if (!selectionCount) return null;

  return (
    <div
      role="region"
      aria-label="Selected rows"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "4px 12px",
        minHeight: 31,
        flexShrink: 0,
        background: `${th.accent}12`,
        borderBottom: `1px solid ${th.accent}44`,
        color: th.text,
        fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
        fontSize: 11,
      }}
    >
      <span style={{ color: th.accent, fontWeight: 700 }}>
        {formatNumber(selectionCount)} selected
      </span>
      <span style={{ color: th.textMuted }}>
        {allRowsSelected
          ? "Current filtered view"
          : hiddenSelectionCount > 0
            ? `${formatNumber(hiddenSelectionCount)} hidden by current filters`
            : "Explicit rows"}
      </span>
      <div style={{ display: "flex", alignItems: "center", gap: 5, marginLeft: "auto" }}>
        <button type="button" onClick={onCopy} style={actionStyle(th, "accent")}>
          Copy selected
        </button>
        <button type="button" onClick={onBulkActions} style={actionStyle(th)}>
          Tag / bookmark
        </button>
        <button type="button" onClick={onClear} style={actionStyle(th)}>
          Clear
        </button>
      </div>
    </div>
  );
}
