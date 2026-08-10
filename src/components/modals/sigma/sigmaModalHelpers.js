import { SEV_ORDER } from "./constants.js";
import { levelsAtOrAboveMinimum } from "../../../utils/sigmaScanPresets.mjs";

export const DETECTION_SETTING_KEYS = [
  "ruleSet",
  "recoverRecords",
  "timelineStart",
  "timelineEnd",
  "utc",
  "provenRules",
  "enableNoisy",
  "enableDeprecated",
  "enableUnsupported",
  "eidFilter",
  "enableAllRules",
  "scanAllEvtxFiles",
  "geoIpEnabled",
  "geoIpDir",
  "outputMode",
  "profile",
  "rulesPath",
  "rulesConfig",
  "includeTags",
  "excludeTags",
  "includeComputers",
  "excludeComputers",
  "includeEids",
  "excludeEids",
  "hayabusaMinSeverity",
];

export const JS_SIGMA_LARGE_TAB_ROWS = 500000;
// Per-logsource-group candidate-row cap for the JS Sigma compatibility scan. The scan
// STREAMS rows (db.iterate, yielding every 1k rows), so this bounds CPU/time, not
// memory — raising it just lets larger imported tabs scan in full. Raw EVTX + Hayabusa
// is still the preferred path for very large datasets.
export const JS_SIGMA_MAX_ROWS_PER_QUERY = 5000000;

export const downloadFile = (content, filename, mime) => {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
};

export const rowsToCsv = (rows) => {
  if (!rows.length) return "";
  const keys = Object.keys(rows[0]);
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return [keys.join(","), ...rows.map((r) => keys.map((k) => esc(r[k])).join(","))].join("\n");
};

export const formatDuration = (ms) => {
  const total = Math.max(0, Math.round(Number(ms || 0) / 1000));
  if (!total) return "0s";
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
};

export const buildDetectionSettingsFromModal = (modal) => Object.fromEntries(
  DETECTION_SETTING_KEYS.map((key) => [key, modal?.[key] ?? (key === "outputMode" ? "csv" : key === "profile" ? "verbose" : key === "ruleSet" ? "all" : "")]),
);

export const applyDetectionSettingsToModal = (state, settings) => {
  const next = { ...state, detectionSettings: settings || {}, detectionSettingsLoaded: true };
  for (const key of DETECTION_SETTING_KEYS) {
    if (settings && Object.prototype.hasOwnProperty.call(settings, key)) next[key] = settings[key];
  }
  const minSeverity = next.hayabusaMinSeverity || "informational";
  const minLevels = levelsAtOrAboveMinimum(minSeverity);
  if (!state.levels) {
    next.levels = Object.fromEntries(SEV_ORDER.map((level) => [level, minLevels.includes(level)]));
  }
  return next;
};

export const activeSuppressedRuleIdsFromModal = (modal) => [
  ...new Set((modal?.ruleSuppressions || [])
    .filter((entry) => entry?.enabled !== false && entry?.ruleId)
    .map((entry) => String(entry.ruleId).trim().toLowerCase())
    .filter(Boolean)),
];

export const wrapTextStyle = {
  display: "block",
  maxWidth: "100%",
  minWidth: 0,
  overflow: "visible",
  whiteSpace: "normal",
  overflowWrap: "anywhere",
  wordBreak: "break-word",
};

export const formatScanDate = (value) => {
  if (!value) return "Unknown time";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "Unknown time" : d.toLocaleString();
};

export const compactPath = (value) => {
  const text = String(value || "");
  if (text.length <= 70) return text;
  const parts = text.split("/");
  if (parts.length <= 3) return `${text.slice(0, 24)}...${text.slice(-36)}`;
  return `.../${parts.slice(-3).join("/")}`;
};
