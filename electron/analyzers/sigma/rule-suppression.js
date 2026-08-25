/**
 * sigma/rule-suppression.js — analyst-managed disabled/noisy rule registry.
 *
 * Global suppressions are synchronized into Hayabusa's noisy_rules.txt so raw
 * EVTX scans inherit the same defaults. Case-specific entries remain metadata
 * for the analyst and are applied by IRFlow-managed JS Sigma scans.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { DEFAULT_NOISY_RULES } = require("./evtx-scanner/default-tuning");

const SETTINGS_DIR = "sigma-detection";
const SUPPRESSIONS_FILE = "rule-suppressions.json";
const MANAGED_BEGIN = "# IRFlow managed noisy rules - begin";
const MANAGED_END = "# IRFlow managed noisy rules - end";

function getUserDataPath() {
  if (process.env.TLE_USER_DATA_PATH) return process.env.TLE_USER_DATA_PATH;
  try {
    const { app } = require("electron");
    if (app?.getPath) return app.getPath("userData");
  } catch {}
  return path.join(os.tmpdir(), "tle-user-data");
}

function getSuppressionDir() {
  return path.join(getUserDataPath(), SETTINGS_DIR);
}

function getSuppressionFile() {
  return path.join(getSuppressionDir(), SUPPRESSIONS_FILE);
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeScopeType(value) {
  return String(value || "").toLowerCase() === "case" ? "case" : "global";
}

function normalizeRuleId(value) {
  return String(value || "").trim();
}

function normalizeSuppression(entry = {}, existing = {}) {
  const scopeType = normalizeScopeType(entry.scopeType || entry.scope_type || existing.scopeType);
  const clean = {
    id: String(entry.id || existing.id || crypto.randomUUID()),
    ruleId: normalizeRuleId(entry.ruleId || entry.rule_id || entry.idValue || ""),
    title: String(entry.title || "").trim(),
    scopeType,
    scope: String(entry.scope || (scopeType === "global" ? "all cases" : "")).trim() || (scopeType === "global" ? "all cases" : "case"),
    reason: String(entry.reason || "").trim(),
    enabled: entry.enabled !== false,
    source: String(entry.source || existing.source || "analyst").trim() || "analyst",
    createdAt: String(entry.createdAt || existing.createdAt || nowIso()),
    updatedAt: String(entry.updatedAt || nowIso()),
  };
  return clean;
}

function defaultSuppressions() {
  const ts = nowIso();
  return DEFAULT_NOISY_RULES.map((rule) => ({
    id: `default-${rule.id}`,
    ruleId: rule.id,
    title: rule.title || rule.comment || rule.id,
    scopeType: "global",
    scope: "all cases",
    reason: rule.comment || "Default noisy rule tuning",
    enabled: true,
    source: "irflow-default",
    createdAt: ts,
    updatedAt: ts,
  }));
}

function mergeDefaults(entries = []) {
  const seenRuleIds = new Set(entries.map((entry) => String(entry.ruleId || "").toLowerCase()).filter(Boolean));
  const merged = [...entries];
  for (const entry of defaultSuppressions()) {
    if (!seenRuleIds.has(entry.ruleId.toLowerCase())) merged.push(entry);
  }
  return merged;
}

function loadRuleSuppressions() {
  try {
    const raw = fs.readFileSync(getSuppressionFile(), "utf8");
    const parsed = JSON.parse(raw);
    const entries = Array.isArray(parsed?.suppressions) ? parsed.suppressions : Array.isArray(parsed) ? parsed : [];
    return mergeDefaults(entries.map((entry) => normalizeSuppression(entry)));
  } catch {
    return defaultSuppressions();
  }
}

function saveRuleSuppressions(entries = []) {
  fs.mkdirSync(getSuppressionDir(), { recursive: true });
  const normalized = [];
  const seen = new Set();
  for (const entry of entries || []) {
    const clean = normalizeSuppression(entry);
    if (!clean.ruleId && !clean.title) continue;
    const key = [
      clean.ruleId.toLowerCase(),
      clean.title.toLowerCase(),
      clean.scopeType,
      clean.scope.toLowerCase(),
    ].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    normalized.push(clean);
  }
  const merged = mergeDefaults(normalized);
  const filePath = getSuppressionFile();
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify({ version: 1, updatedAt: nowIso(), suppressions: merged }, null, 2), "utf8");
  fs.renameSync(tmpPath, filePath);
  return merged;
}

function activeSuppressedRuleIds(entries = loadRuleSuppressions(), { includeCase = true } = {}) {
  const ids = new Set();
  for (const entry of entries || []) {
    const clean = normalizeSuppression(entry);
    if (!clean.enabled || !clean.ruleId) continue;
    if (!includeCase && clean.scopeType === "case") continue;
    ids.add(clean.ruleId.toLowerCase());
  }
  return [...ids];
}

function stripManagedBlock(contents) {
  const lines = String(contents || "").split(/\r?\n/);
  const out = [];
  let inBlock = false;
  for (const line of lines) {
    if (line.trim() === MANAGED_BEGIN) {
      inBlock = true;
      continue;
    }
    if (line.trim() === MANAGED_END) {
      inBlock = false;
      continue;
    }
    if (!inBlock) out.push(line);
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd();
}

function existingNoisyRuleIds(contents) {
  const ids = new Set();
  for (const line of String(contents || "").split(/\r?\n/)) {
    const match = line.match(/^\s*([0-9a-f]{8}-[0-9a-f-]{27,})/i);
    if (match) ids.add(match[1].toLowerCase());
  }
  return ids;
}

function removeManagedRuleLines(contents, managedIds) {
  if (!managedIds?.size) return String(contents || "");
  return String(contents || "").split(/\r?\n/)
    .filter((line) => {
      const match = line.match(/^\s*([0-9a-f]{8}-[0-9a-f-]{27,})/i);
      return !match || !managedIds.has(match[1].toLowerCase());
    })
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trimEnd();
}

function noisyRuleLine(entry) {
  const parts = [];
  if (entry.title) parts.push(entry.title);
  if (entry.reason && entry.reason !== entry.title) parts.push(entry.reason);
  const comment = parts.join(" - ").replace(/\s+/g, " ").trim();
  return `${entry.ruleId}${comment ? ` # ${comment}` : ""}`;
}

function syncHayabusaNoisyRules(entries = loadRuleSuppressions(), { configDir } = {}) {
  if (!configDir) return { synced: false, path: null, count: 0, error: "Hayabusa rules config directory not available" };
  try {
    fs.mkdirSync(configDir, { recursive: true });
    const noisyPath = path.join(configDir, "noisy_rules.txt");
    const original = fs.existsSync(noisyPath) ? fs.readFileSync(noisyPath, "utf8") : "";
    const normalizedEntries = (entries || []).map((entry) => normalizeSuppression(entry));
    const managedIds = new Set(normalizedEntries
      .filter((entry) => entry.scopeType === "global" && entry.ruleId)
      .map((entry) => entry.ruleId.toLowerCase()));
    const base = removeManagedRuleLines(stripManagedBlock(original), managedIds);
    const existing = existingNoisyRuleIds(base);
    const managedEntries = normalizedEntries
      .filter((entry) => entry.enabled && entry.ruleId && entry.scopeType === "global" && !existing.has(entry.ruleId.toLowerCase()));
    const managedBlock = managedEntries.length
      ? [MANAGED_BEGIN, ...managedEntries.map(noisyRuleLine), MANAGED_END].join("\n")
      : "";
    const next = [base, managedBlock].filter(Boolean).join(base && managedBlock ? "\n\n" : "") + "\n";
    fs.writeFileSync(noisyPath, next, "utf8");
    return { synced: true, path: noisyPath, count: managedEntries.length };
  } catch (err) {
    return { synced: false, path: configDir ? path.join(configDir, "noisy_rules.txt") : null, count: 0, error: err.message || String(err) };
  }
}

module.exports = {
  MANAGED_BEGIN,
  MANAGED_END,
  defaultSuppressions,
  activeSuppressedRuleIds,
  getSuppressionFile,
  loadRuleSuppressions,
  normalizeSuppression,
  saveRuleSuppressions,
  syncHayabusaNoisyRules,
};
