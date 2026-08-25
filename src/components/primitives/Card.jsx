import useTheme from "../../hooks/useTheme.js";

/**
 * Bordered section box used inside modals to group related controls.
 * Optionally renders a small uppercase label above the content.
 */
export default function Card({ label, padding = "12px 14px", style: extraStyle, children }) {
  const { th } = useTheme();
  return (
    <div
      style={{
        background: th.bgInput,
        border: `1px solid ${th.border}`,
        borderRadius: 8,
        padding,
        ...extraStyle,
      }}
    >
      {label && (
        <div
          style={{
            fontSize: 11,
            color: th.textDim,
            marginBottom: 6,
            fontWeight: 500,
            fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
          }}
        >
          {label}
        </div>
      )}
      {children}
    </div>
  );
}
