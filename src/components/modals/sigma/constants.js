// Theme-aware Sigma severity palette. The static const used to inline raw hex
// (e.g. "#f85149") — now sourced from the theme so light/dark variants apply.
// Use as: `const SEV_COLORS = sevColorsFor(th);` inside any component with `th`.
export const sevColorsFor = (th) => ({
  critical: th.sev.critical,
  high: th.sev.high,
  medium: th.sev.med,
  low: th.sev.low,
  informational: th.textMuted,
});

export const SEV_ORDER = ["critical", "high", "medium", "low", "informational"];
export const STATUS_LIST = ["stable", "test", "experimental"];

// Single-screen flow: target/preset/validate are collapsed onto one "Configure"
// surface, so the progress rail is now just three phase nodes.
export const WIZARD_STEPS = [
  { id: "config", label: "Configure" },
  { id: "scan", label: "Scan" },
  { id: "triage", label: "Findings" },
];
