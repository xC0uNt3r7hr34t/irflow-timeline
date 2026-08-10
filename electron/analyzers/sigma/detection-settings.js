/**
 * sigma/detection-settings.js — persistent global detection scan defaults.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const SETTINGS_DIR = "sigma-detection";
const SETTINGS_FILE = "settings.json";

const DEFAULT_DETECTION_SETTINGS = {
  ruleSet: "all",
  recoverRecords: false,
  timelineStart: "",
  timelineEnd: "",
  utc: false,
  provenRules: false,
  enableNoisy: false,
  enableDeprecated: false,
  enableUnsupported: false,
  eidFilter: false,
  enableAllRules: false,
  scanAllEvtxFiles: false,
  geoIpEnabled: false,
  geoIpDir: "",
  outputMode: "csv",
  profile: "verbose",
  rulesPath: "",
  rulesConfig: "",
  includeTags: "",
  excludeTags: "",
  includeComputers: "",
  excludeComputers: "",
  includeEids: "",
  excludeEids: "",
  hayabusaMinSeverity: "informational",
};

const BOOL_KEYS = new Set([
  "recoverRecords",
  "utc",
  "provenRules",
  "enableNoisy",
  "enableDeprecated",
  "enableUnsupported",
  "eidFilter",
  "enableAllRules",
  "scanAllEvtxFiles",
  "geoIpEnabled",
]);

const STRING_KEYS = new Set(Object.keys(DEFAULT_DETECTION_SETTINGS).filter((key) => !BOOL_KEYS.has(key)));
const VALID_MIN_SEVERITIES = new Set(["critical", "high", "medium", "low", "informational"]);
const VALID_OUTPUT_MODES = new Set(["csv", "json", "jsonl"]);

function getUserDataPath() {
  if (process.env.TLE_USER_DATA_PATH) return process.env.TLE_USER_DATA_PATH;
  try {
    const { app } = require("electron");
    if (app?.getPath) return app.getPath("userData");
  } catch {}
  return path.join(os.tmpdir(), "tle-user-data");
}

function getSettingsDir() {
  return path.join(getUserDataPath(), SETTINGS_DIR);
}

function getSettingsFile() {
  return path.join(getSettingsDir(), SETTINGS_FILE);
}

function ensureDir() {
  fs.mkdirSync(getSettingsDir(), { recursive: true });
}

function normalizeDetectionSettings(settings = {}) {
  const clean = { ...DEFAULT_DETECTION_SETTINGS };
  for (const key of BOOL_KEYS) clean[key] = !!settings[key];
  for (const key of STRING_KEYS) {
    if (settings[key] != null) clean[key] = String(settings[key]);
  }
  if (!VALID_MIN_SEVERITIES.has(clean.hayabusaMinSeverity)) clean.hayabusaMinSeverity = DEFAULT_DETECTION_SETTINGS.hayabusaMinSeverity;
  if (!VALID_OUTPUT_MODES.has(clean.outputMode)) clean.outputMode = DEFAULT_DETECTION_SETTINGS.outputMode;
  if (!clean.profile.trim()) clean.profile = DEFAULT_DETECTION_SETTINGS.profile;
  if (!clean.ruleSet.trim()) clean.ruleSet = DEFAULT_DETECTION_SETTINGS.ruleSet;
  return clean;
}

function loadDetectionSettings() {
  try {
    const raw = fs.readFileSync(getSettingsFile(), "utf8");
    return normalizeDetectionSettings(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_DETECTION_SETTINGS };
  }
}

function saveDetectionSettings(settings = {}) {
  ensureDir();
  const clean = normalizeDetectionSettings(settings);
  const filePath = getSettingsFile();
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(clean, null, 2), "utf8");
  fs.renameSync(tmpPath, filePath);
  return clean;
}

function getDetectionSettingsPathEntries(settings = {}) {
  const clean = normalizeDetectionSettings(settings);
  const entries = [];
  const add = (key, scopes, recursive, label) => {
    const targetPath = String(clean[key] || "").trim();
    if (!targetPath) return;
    entries.push({
      key,
      path: targetPath,
      scopes: Array.isArray(scopes) ? scopes : [scopes],
      recursive,
      label,
    });
  };

  add("rulesPath", ["hayabusa-rules", "compat-rules"], true, "Saved custom rules directory");
  add("rulesConfig", ["hayabusa-rules-config", "hayabusa-rules"], false, "Saved rules config file");
  add("geoIpDir", "geoip", true, "Saved GeoIP directory");
  return entries;
}

module.exports = {
  DEFAULT_DETECTION_SETTINGS,
  getDetectionSettingsPathEntries,
  getSettingsFile,
  loadDetectionSettings,
  normalizeDetectionSettings,
  saveDetectionSettings,
};
