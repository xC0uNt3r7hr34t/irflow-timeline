const test = require("node:test");
const assert = require("node:assert/strict");
const { pathToFileURL } = require("node:url");

async function loadPresetUtils() {
  const url = pathToFileURL(require.resolve("../src/utils/sigmaScanPresets.mjs")).href;
  return import(url);
}

test("built-in fast preset applies high-confidence filters and Hayabusa options", async () => {
  const {
    BUILTIN_SIGMA_SCAN_PRESETS,
    applySigmaScanPresetState,
  } = await loadPresetUtils();

  const preset = BUILTIN_SIGMA_SCAN_PRESETS.find((p) => p.id === "fast-high-confidence");
  const next = applySigmaScanPresetState({
    type: "sigma",
    scanMode: "evtx-dir",
    evtxDir: { dirPath: "/case/evtx" },
    timelineStart: "2026-01-01 00:00:00",
    scanPreflight: { ok: true },
  }, preset);

  assert.equal(next.levels.critical, true);
  assert.equal(next.levels.high, true);
  assert.equal(next.levels.medium, false);
  assert.equal(next.hayabusaMinSeverity, "high");
  assert.equal(next.statuses.stable, true);
  assert.equal(next.statuses.test, true);
  assert.equal(next.statuses.experimental, false);
  assert.equal(next.ruleSet, "core");
  assert.equal(next.provenRules, true);
  assert.equal(next.eidFilter, true);
  assert.equal(next.scanPreflight, null);
  assert.equal(next.evtxDir.dirPath, "/case/evtx");
  assert.equal(next.timelineStart, "2026-01-01 00:00:00");
});

test("custom scan preset captures reusable scan choices without case paths", async () => {
  const { buildSigmaScanPresetFromModal } = await loadPresetUtils();

  const preset = buildSigmaScanPresetFromModal({
    scanMode: "tab",
    levels: { critical: true, high: true, medium: false, low: false, informational: false },
    statuses: { stable: true, test: false, experimental: false },
    selectedCategories: ["process_creation", "powershell"],
    ruleSet: "all",
    provenRules: true,
    eidFilter: true,
    enableNoisy: false,
    scanAllEvtxFiles: false,
    outputMode: "jsonl",
    profile: "verbose",
    evtxDir: { dirPath: "/case/evtx" },
    timelineStart: "2026-01-01",
    rulesPath: "/case/rules",
  }, { name: "Case triage" });

  assert.equal(preset.name, "Case triage");
  assert.deepEqual(preset.levels, ["critical", "high"]);
  assert.equal(preset.hayabusaMinSeverity, "high");
  assert.deepEqual(preset.statuses, ["stable"]);
  assert.deepEqual(preset.categories, ["process_creation", "powershell"]);
  assert.equal(preset.provenRules, true);
  assert.equal(preset.eidFilter, true);
  assert.equal(preset.outputMode, "jsonl");
  assert.equal(Object.prototype.hasOwnProperty.call(preset, "evtxDir"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(preset, "timelineStart"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(preset, "rulesPath"), false);
});

test("minimum severity helpers map Hayabusa thresholds to included levels", async () => {
  const { levelsAtOrAboveMinimum, minimumSeverityFromLevels } = await loadPresetUtils();

  assert.deepEqual(levelsAtOrAboveMinimum("medium"), ["critical", "high", "medium"]);
  assert.equal(minimumSeverityFromLevels(["critical", "high"]), "high");
  assert.equal(minimumSeverityFromLevels(["critical", "medium"]), "medium");
});

test("saved scan presets are sanitized before persistence", async () => {
  const { sanitizeSigmaScanPresets } = await loadPresetUtils();

  const presets = sanitizeSigmaScanPresets([
    { id: "builtin", name: "Built in", builtin: true },
    { id: "bad", name: "", levels: ["critical"] },
    { id: "ok", name: "Valid", levels: ["critical", "bad"], statuses: ["stable", "draft"], categories: ["a", "a", ""] },
  ]);

  assert.equal(presets.length, 1);
  assert.equal(presets[0].id, "ok");
  assert.deepEqual(presets[0].levels, ["critical"]);
  assert.deepEqual(presets[0].statuses, ["stable"]);
  assert.deepEqual(presets[0].categories, ["a"]);
});
