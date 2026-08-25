import { TIMELINE_PALETTE, TIMELINE_PALETTE_LIGHT } from "../constants/timeline-palette.js";

// Pre-compile color rules for fast per-row matching (avoids repeated toLowerCase + regex construction)
export function compileColorRules(rules) {
  return rules.map((r) => {
    const v = r.value.toLowerCase();
    let test;
    if (r.condition === "contains") test = (cv) => cv.includes(v);
    else if (r.condition === "equals") test = (cv) => cv === v;
    else if (r.condition === "startswith") test = (cv) => cv.startsWith(v);
    else if (r.condition === "regex") {
      try { const re = new RegExp(r.value, "i"); test = (_cv, raw) => re.test(raw); }
      catch { test = () => false; }
    } else test = () => false;
    return { column: r.column, test, bg: r.bgColor, fg: r.fgColor };
  });
}

export function applyColors(row, compiledRules) {
  for (const r of compiledRules) {
    const raw = row[r.column] || "";
    if (r.test(raw.toLowerCase(), raw)) return { bg: r.bg, fg: r.fg };
  }
  return null;
}

const MAX_TIMELINE_COLOR_RULES = 150;

export function buildTimelineColorRules(rows, colName, isDark) {
  const palette = isDark ? TIMELINE_PALETTE : TIMELINE_PALETTE_LIGHT;
  const seen = new Map();
  for (const row of rows) {
    const val = (row[colName] || "").trim();
    if (val && !seen.has(val)) {
      seen.set(val, seen.size);
      if (seen.size >= MAX_TIMELINE_COLOR_RULES) break;
    }
  }
  return Array.from(seen.entries()).map(([val, idx]) => {
    const p = palette[idx % palette.length];
    return { column: colName, condition: "equals", value: val, bgColor: p.bg, fgColor: p.fg };
  });
}
