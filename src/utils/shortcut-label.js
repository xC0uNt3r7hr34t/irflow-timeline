/** Platform-aware keyboard shortcut labels for the renderer UI. */

export const IS_MAC = typeof navigator !== "undefined"
  && /Mac|iPod|iPhone|iPad/.test(navigator.platform || "");

export const MOD = IS_MAC ? "⌘" : "Ctrl";
export const MOD_CLICK = IS_MAC ? "⌘+Click" : "Ctrl+Click";

/** Format a modifier+key shortcut for display, e.g. mod("O") → "Ctrl+O" or "⌘O". */
export function mod(key, { shift = false } = {}) {
  const prefix = shift ? (IS_MAC ? "⇧⌘" : "Ctrl+Shift+") : (IS_MAC ? "⌘" : "Ctrl+");
  return `${prefix}${key}`;
}

/** Replace macOS ⌘ symbols in a shortcut string with the platform modifier. */
export function adaptShortcut(label) {
  if (!label || IS_MAC) return label;
  return String(label)
    .replace(/⇧⌘/g, "Ctrl+Shift+")
    .replace(/⌘⇧/g, "Ctrl+Shift+")
    .replace(/⌘/g, "Ctrl+");
}

/** Shortcut rows for the Keyboard Shortcuts modal. */
export function getShortcutRows(searchBehaviors = []) {
  const next = IS_MAC ? "F3 / ⌘→" : "F3 / Ctrl+→";
  const prev = IS_MAC ? "⇧F3 / ⌘←" : "Shift+F3 / Ctrl+←";
  const font = IS_MAC ? "⌘ + / ⌘ -" : "Ctrl+ + / Ctrl+ -";
  return [
    [mod("K"), "Open command palette"],
    [mod("O"), "Open file"],
    [mod("E"), "Export filtered view"],
    [mod("R", { shift: true }), "Generate report"],
    [mod("S"), "Save session"],
    [mod("O", { shift: true }), "Open session"],
    [mod("W"), "Close tab"],
    [mod("Q", { shift: true }), "Close all tabs"],
    [mod("F"), "Focus search"],
    [mod("F", { shift: true }), "Find in all tabs"],
    [next, "Next search match"],
    [prev, "Previous search match"],
    ["↑ / ↓", "Navigate rows"],
    [mod("B"), "Toggle bookmarked only"],
    [mod("C", { shift: true }), "Column Manager"],
    [mod("L", { shift: true }), "Conditional Formatting"],
    [mod("R"), "Reset column widths"],
    [font, "Font size increase / decrease"],
    [mod("C"), "Copy selected rows"],
    ["Shift+Click", "Select range"],
    [MOD_CLICK, "Cell quick actions"],
    ["⌃+Click", "Cell quick actions (alternate)"],
    ["⇧F10", "Context menu (keyboard)"],
    [searchBehaviors.map((item) => item.label).join(" / "), "Switch search behavior"],
    ["⏱ icon", "Date range filter (timestamp cols)"],
    ["Dbl-click", "Cell detail popup"],
    ["Dbl-click border", "Auto-fit column"],
    ["Drag header", "Group by column"],
    ["Esc", "Close panel/modal"],
  ];
}
