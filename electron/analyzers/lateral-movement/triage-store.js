/**
 * lateral-movement/triage-store.js — persistent review state for LM results.
 *
 * This intentionally stores analyst review decisions separately from analyzer
 * output so re-running a tab can pick up prior reviewed/false-positive marks
 * without mutating the detection result itself.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const SETTINGS_DIR = "lateral-movement";
const TRIAGE_FILE = "triage-state.json";
const MAX_SCOPES = 250;

function getUserDataPath() {
  if (process.env.TLE_USER_DATA_PATH) return process.env.TLE_USER_DATA_PATH;
  try {
    const { app } = require("electron");
    if (app?.getPath) return app.getPath("userData");
  } catch {}
  return path.join(os.tmpdir(), "tle-user-data");
}

function getTriageDir() {
  return path.join(getUserDataPath(), SETTINGS_DIR);
}

function getTriageFile() {
  return path.join(getTriageDir(), TRIAGE_FILE);
}

function ensureDir() {
  fs.mkdirSync(getTriageDir(), { recursive: true });
}

function safeString(value, max = 500) {
  return String(value || "").trim().slice(0, max);
}

function hashString(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, 24);
}

function normalizeScope(scope = {}) {
  if (typeof scope === "string") {
    const raw = safeString(scope);
    return { id: raw || hashString("default"), label: raw || "default", tabIds: [] };
  }
  const tabIds = Array.isArray(scope.tabIds)
    ? [...new Set(scope.tabIds.map((id) => safeString(id, 120)).filter(Boolean))]
    : [];
  const label = safeString(scope.label || scope.name || tabIds.join(", ") || "lateral movement analysis");
  const rawId = safeString(scope.id || scope.scopeId);
  const id = rawId || hashString(`${label}|${tabIds.join("|")}|${safeString(scope.rowFingerprint || "")}`);
  return {
    id,
    label,
    tabIds,
    rowFingerprint: safeString(scope.rowFingerprint || "", 1000),
  };
}

function normalizeMarkMap(map = {}) {
  const out = {};
  if (!map || typeof map !== "object" || Array.isArray(map)) return out;
  for (const [key, value] of Object.entries(map)) {
    const k = safeString(key, 200);
    if (!k) continue;
    out[k] = safeString(value, 80) || new Date().toISOString();
  }
  return out;
}

function normalizeTriageState(state = {}) {
  return {
    version: 1,
    reviewed: normalizeMarkMap(state.reviewed),
    falsePositive: normalizeMarkMap(state.falsePositive),
    updatedAt: safeString(state.updatedAt, 80) || null,
  };
}

function normalizeStore(store = {}) {
  const scopes = {};
  const entries = Object.entries(store.scopes || {})
    .filter(([key]) => safeString(key, 200))
    .sort((a, b) => String(b[1]?.updatedAt || "").localeCompare(String(a[1]?.updatedAt || "")))
    .slice(0, MAX_SCOPES);
  for (const [key, record] of entries) {
    const scope = normalizeScope(record?.scope || { id: key });
    scopes[scope.id || key] = {
      scope,
      state: normalizeTriageState(record?.state || record),
      updatedAt: safeString(record?.updatedAt, 80) || safeString(record?.state?.updatedAt, 80) || null,
    };
  }
  return { version: 1, scopes };
}

function loadStore() {
  try {
    return normalizeStore(JSON.parse(fs.readFileSync(getTriageFile(), "utf8")));
  } catch {
    return normalizeStore({});
  }
}

function saveStore(store = {}) {
  ensureDir();
  const clean = normalizeStore(store);
  const filePath = getTriageFile();
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(clean, null, 2), "utf8");
  fs.renameSync(tmpPath, filePath);
  return clean;
}

function loadLateralMovementTriage(scope = {}) {
  const cleanScope = normalizeScope(scope);
  const store = loadStore();
  return normalizeTriageState(store.scopes[cleanScope.id]?.state);
}

function saveLateralMovementTriage(scope = {}, state = {}) {
  const cleanScope = normalizeScope(scope);
  const cleanState = normalizeTriageState({
    ...state,
    updatedAt: safeString(state.updatedAt, 80) || new Date().toISOString(),
  });
  const store = loadStore();
  store.scopes[cleanScope.id] = {
    scope: cleanScope,
    state: cleanState,
    updatedAt: cleanState.updatedAt,
  };
  saveStore(store);
  return cleanState;
}

function clearLateralMovementTriage(scope = {}) {
  const cleanScope = normalizeScope(scope);
  const store = loadStore();
  delete store.scopes[cleanScope.id];
  saveStore(store);
  return normalizeTriageState({});
}

module.exports = {
  clearLateralMovementTriage,
  getTriageFile,
  loadLateralMovementTriage,
  loadStore,
  normalizeScope,
  normalizeTriageState,
  saveLateralMovementTriage,
  saveStore,
};
