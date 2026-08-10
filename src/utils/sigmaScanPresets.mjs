const LEVELS = ["critical", "high", "medium", "low", "informational"];
const STATUSES = ["stable", "test", "experimental"];
const EVTX_OPTION_KEYS = [
  "ruleSet",
  "recoverRecords",
  "utc",
  "provenRules",
  "enableNoisy",
  "enableDeprecated",
  "enableUnsupported",
  "eidFilter",
  "enableAllRules",
  "scanAllEvtxFiles",
  "outputMode",
  "profile",
  "hayabusaMinSeverity",
];

export const SIGMA_SCAN_LEVELS = LEVELS;
export const SIGMA_SCAN_STATUSES = STATUSES;

export const BUILTIN_SIGMA_SCAN_PRESETS = [
  {
    id: "fast-high-confidence",
    name: "Fast high-confidence only",
    builtin: true,
    levels: ["critical", "high"],
    hayabusaMinSeverity: "high",
    statuses: ["stable", "test"],
    categories: null,
    ruleSet: "core",
    profile: "standard",
    outputMode: "csv",
    provenRules: true,
    eidFilter: true,
    enableNoisy: false,
    enableDeprecated: false,
    enableUnsupported: false,
    enableAllRules: false,
    scanAllEvtxFiles: false,
  },
  {
    id: "full-hunt",
    name: "Full hunt",
    builtin: true,
    levels: LEVELS,
    hayabusaMinSeverity: "informational",
    statuses: STATUSES,
    categories: null,
    ruleSet: "all",
    profile: "verbose",
    outputMode: "csv",
    provenRules: false,
    eidFilter: false,
    enableNoisy: true,
    enableDeprecated: false,
    enableUnsupported: false,
    enableAllRules: false,
    scanAllEvtxFiles: true,
  },
  {
    id: "critical-high-only",
    name: "Critical/high only",
    builtin: true,
    levels: ["critical", "high"],
    hayabusaMinSeverity: "high",
    statuses: STATUSES,
    categories: null,
    ruleSet: "all",
    profile: "verbose",
    outputMode: "csv",
    provenRules: false,
    eidFilter: false,
    enableNoisy: false,
    enableDeprecated: false,
    enableUnsupported: false,
    enableAllRules: false,
    scanAllEvtxFiles: false,
  },
];

function listFromMap(map, keys) {
  if (!map || typeof map !== "object") return keys.slice();
  return keys.filter((key) => map[key] !== false);
}

export function levelMapFromList(levels = LEVELS) {
  const selected = new Set(Array.isArray(levels) && levels.length > 0 ? levels : LEVELS);
  return Object.fromEntries(LEVELS.map((level) => [level, selected.has(level)]));
}

export function statusMapFromList(statuses = STATUSES) {
  const selected = new Set(Array.isArray(statuses) && statuses.length > 0 ? statuses : STATUSES);
  return Object.fromEntries(STATUSES.map((status) => [status, selected.has(status)]));
}

export function levelsAtOrAboveMinimum(minSeverity = "informational") {
  const idx = LEVELS.indexOf(minSeverity);
  if (idx < 0) return LEVELS.slice();
  return LEVELS.slice(0, idx + 1);
}

export function minimumSeverityFromLevels(levels = LEVELS) {
  if (!Array.isArray(levels) || levels.length === 0) return null;
  let selectedIdx = -1;
  for (const level of levels) {
    const idx = LEVELS.indexOf(level);
    if (idx > selectedIdx) selectedIdx = idx;
  }
  return selectedIdx >= 0 ? LEVELS[selectedIdx] : null;
}

export function normalizePresetCategories(categories) {
  if (!Array.isArray(categories)) return null;
  const clean = categories.map((cat) => String(cat || "").trim()).filter(Boolean);
  return clean.length > 0 ? [...new Set(clean)] : [];
}

export function applySigmaScanPresetState(currentModal = {}, preset = {}) {
  const patch = {
    levels: levelMapFromList(preset.levels),
    statuses: statusMapFromList(preset.statuses),
    selectedCategories: normalizePresetCategories(preset.categories),
    activeScanPresetId: preset.id || null,
    activeScanPresetName: preset.name || null,
    scanPreflight: null,
    error: null,
  };

  for (const key of EVTX_OPTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(preset, key)) {
      patch[key] = preset[key];
    }
  }

  // Keep current case-specific paths, dates, and target selections intact.
  return { ...currentModal, ...patch };
}

export function buildSigmaScanPresetFromModal(modal = {}, options = {}) {
  const name = String(options.name || "").trim();
  if (!name) throw new Error("Preset name is required.");

  const preset = {
    id: options.id || `custom-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    name,
    builtin: false,
    createdAt: options.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    scanMode: modal.scanMode || "evtx-dir",
    levels: listFromMap(modal.levels, LEVELS),
    hayabusaMinSeverity: modal.hayabusaMinSeverity || minimumSeverityFromLevels(listFromMap(modal.levels, LEVELS)) || "informational",
    statuses: listFromMap(modal.statuses, STATUSES),
    categories: normalizePresetCategories(modal.selectedCategories),
    ruleSet: modal.ruleSet || "all",
    recoverRecords: !!modal.recoverRecords,
    utc: !!modal.utc,
    provenRules: !!modal.provenRules,
    enableNoisy: !!modal.enableNoisy,
    enableDeprecated: !!modal.enableDeprecated,
    enableUnsupported: !!modal.enableUnsupported,
    eidFilter: !!modal.eidFilter,
    enableAllRules: !!modal.enableAllRules,
    scanAllEvtxFiles: !!modal.scanAllEvtxFiles,
    outputMode: modal.outputMode || "csv",
    profile: modal.profile || "verbose",
  };

  return preset;
}

export function sanitizeSigmaScanPresets(presets) {
  if (!Array.isArray(presets)) return [];
  return presets
    .filter((preset) => preset && !preset.builtin && typeof preset.name === "string")
    .map((preset) => ({
      ...preset,
      id: preset.id || `custom-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
      name: preset.name.trim(),
      levels: Array.isArray(preset.levels) ? preset.levels.filter((level) => LEVELS.includes(level)) : LEVELS,
      hayabusaMinSeverity: LEVELS.includes(preset.hayabusaMinSeverity) ? preset.hayabusaMinSeverity : minimumSeverityFromLevels(preset.levels) || "informational",
      statuses: Array.isArray(preset.statuses) ? preset.statuses.filter((status) => STATUSES.includes(status)) : STATUSES,
      categories: normalizePresetCategories(preset.categories),
      builtin: false,
    }))
    .filter((preset) => preset.name);
}

export function summarizeSigmaScanPreset(preset = {}) {
  const levels = Array.isArray(preset.levels) && preset.levels.length > 0 ? preset.levels : LEVELS;
  const statuses = Array.isArray(preset.statuses) && preset.statuses.length > 0 ? preset.statuses : STATUSES;
  const categories = normalizePresetCategories(preset.categories);
  const chunks = [
    levels.length === LEVELS.length ? "all severities" : levels.join("/"),
    statuses.length === STATUSES.length ? "all statuses" : statuses.join("/"),
  ];

  if (categories && categories.length > 0) chunks.push(`${categories.length} categories`);
  if (preset.ruleSet && preset.ruleSet !== "all") chunks.push(`${preset.ruleSet} rules`);
  if (preset.provenRules) chunks.push("proven");
  if (preset.eidFilter) chunks.push("EID filter");
  if (preset.enableNoisy) chunks.push("noisy");
  if (preset.scanAllEvtxFiles) chunks.push("all EVTX");
  return chunks.join(" | ");
}
