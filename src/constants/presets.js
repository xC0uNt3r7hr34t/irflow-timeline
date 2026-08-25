export const PRESETS = [
  { label: "PowerShell", column: "Process", condition: "contains", value: "powershell", bgColor: "#7f1d1d", fgColor: "#fca5a5" },
  { label: "Mimikatz", column: "Message", condition: "contains", value: "mimikatz", bgColor: "#581c87", fgColor: "#d8b4fe" },
  { label: "PsExec", column: "Process", condition: "contains", value: "psexec", bgColor: "#713f12", fgColor: "#fde68a" },
  { label: "LSASS", column: "Message", condition: "contains", value: "lsass", bgColor: "#064e3b", fgColor: "#6ee7b7" },
  { label: "Critical", column: "Level", condition: "equals", value: "Critical", bgColor: "#991b1b", fgColor: "#ffffff" },
  { label: "Error", column: "Level", condition: "equals", value: "Error", bgColor: "#92400e", fgColor: "#fde68a" },
  { label: "C2 / DNS", column: "Message", condition: "contains", value: "c2.", bgColor: "#1e3a5f", fgColor: "#93c5fd" },
  { label: "Encoded Cmd", column: "Message", condition: "contains", value: "encoded", bgColor: "#4c1d95", fgColor: "#c4b5fd" },
];

export const TAG_PRESETS = {
  "Suspicious": "#f85149",
  "Lateral Movement": "#f0883e",
  "Exfiltration": "#a371f7",
  "Persistence": "#58a6ff",
  "C2": "#da3633",
  "Initial Access": "#3fb950",
  "Credential Access": "#d29922",
  "Execution": "#ff7b72",
};

export const SUS_COLORS = { 3: "#f85149", 2: "#f0883e", 1: "#d29922", 0: null };
export const INT_COLOR = { System: "#f85149", High: "#f0883e", Medium: "#d29922", Low: "#8b949e", Untrusted: "#6e40c9" };

// Theme-aware variants — use these in components that have access to `th`.
// Mirror SUS_COLORS / INT_COLOR but pull from the theme's `sev` palette so light
// mode gets darker shades for contrast and the tokens stay centralised.
export const susColorsFor = (th) => ({ 3: th.sev.critical, 2: th.sev.high, 1: th.sev.med, 0: null });
export const intColorFor = (th) => ({ System: th.sev.critical, High: th.sev.high, Medium: th.sev.med, Low: th.sev.low, Untrusted: th.sev.custom });

// Process Inspector deliberately uses a restrained IRFlow-only palette:
// orange for analyst attention and neutral theme tokens for context. Severity
// remains explicit in text, score, and ordering instead of relying on a
// red/amber/green rainbow that becomes noisy in dense process views.
export const processInspectorPaletteFor = (th) => ({
  severity: { 3: th.accent, 2: th.accent, 1: th.textDim, 0: th.border },
  ruleSeverity: {
    critical: th.accent,
    high: th.accent,
    medium: th.textDim,
    low: th.textMuted,
  },
  integrity: {
    System: th.textDim,
    High: th.textDim,
    Medium: th.textMuted,
    Low: th.textMuted,
    Untrusted: th.accent,
  },
});

// Re-exports kept for non-PA consumers (utils/process-inspector.js) to avoid
// reaching into the components/ tree. Source of truth lives in
// src/components/process-analyzer/constants.js.
export { PT_ICON_STYLE, PT_VIEW_MODES, PI_ANALYST_PROFILE_DEFAULT } from "../components/process-analyzer/constants.js";
