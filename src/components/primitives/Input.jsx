import { forwardRef } from "react";
import useTheme from "../../hooks/useTheme.js";

/**
 * Themed text input matching the existing modal/filter look.
 * Use `as="textarea"` for multiline.
 */
const Input = forwardRef(function Input(
  { as = "input", size = "md", fullWidth = true, style: extraStyle, ...rest },
  ref
) {
  const { th } = useTheme();
  const sizeMap = {
    sm: { padding: "4px 6px", fontSize: 11 },
    md: { padding: "6px 8px", fontSize: 12 },
    lg: { padding: "8px 10px", fontSize: 13 },
  };
  const sz = sizeMap[size] || sizeMap.md;

  const Tag = as;
  return (
    <Tag
      ref={ref}
      style={{
        ...sz,
        background: th.bgInput,
        color: th.text,
        border: `1px solid ${th.border}`,
        borderRadius: 4,
        outline: "none",
        fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
        width: fullWidth ? "100%" : undefined,
        boxSizing: "border-box",
        ...extraStyle,
      }}
      {...rest}
    />
  );
});

export default Input;
