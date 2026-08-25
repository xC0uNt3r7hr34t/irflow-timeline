/**
 * sigma/scan-history.js — persistent Sigma/Hayabusa scan history.
 *
 * Result databases are copied out of the temporary job store so exports,
 * report viewing, and "Open as Tab" keep working after the modal closes or
 * after the app restarts.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { SigmaResultStore } = require("./result-store");

const HISTORY_DIR = "sigma-scan-history";
const HISTORY_FILE = "history.json";
const SETTINGS_FILE = "settings.json";
const MAX_HISTORY_RECORDS = 200;
const DEFAULT_SETTINGS = {
  retentionDays: 0,
};
const EMPTY_TRIAGE_STATE = {
  reviewedRules: {},
  falsePositiveRules: {},
  taggedRules: {},
  bookmarkedRules: {},
};

function getUserDataPath() {
  if (process.env.TLE_USER_DATA_PATH) return process.env.TLE_USER_DATA_PATH;
  try {
    const { app } = require("electron");
    if (app?.getPath) return app.getPath("userData");
  } catch {}
  return path.join(os.tmpdir(), "tle-user-data");
}

function getHistoryDir() {
  return path.join(getUserDataPath(), HISTORY_DIR);
}

function getResultsDir() {
  return path.join(getHistoryDir(), "results");
}

function getHistoryFile() {
  return path.join(getHistoryDir(), HISTORY_FILE);
}

function getSettingsFile() {
  return path.join(getHistoryDir(), SETTINGS_FILE);
}

function ensureDirs() {
  fs.mkdirSync(getResultsDir(), { recursive: true });
}

function readHistoryFile() {
  try {
    const raw = fs.readFileSync(getHistoryFile(), "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeHistoryFile(records) {
  ensureDirs();
  const filePath = getHistoryFile();
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(records, null, 2), "utf8");
  fs.renameSync(tmpPath, filePath);
}

function normalizeSettings(settings = {}) {
  const retentionDays = Math.max(0, Math.min(3650, safeInt(settings.retentionDays, DEFAULT_SETTINGS.retentionDays)));
  return { ...DEFAULT_SETTINGS, retentionDays };
}

function readSettingsFile() {
  try {
    const raw = fs.readFileSync(getSettingsFile(), "utf8");
    return normalizeSettings(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function writeSettingsFile(settings) {
  ensureDirs();
  const clean = normalizeSettings(settings);
  const filePath = getSettingsFile();
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(clean, null, 2), "utf8");
  fs.renameSync(tmpPath, filePath);
  return clean;
}

function createHistoryId(now = Date.now()) {
  return `scan_${now}_${crypto.randomBytes(4).toString("hex")}`;
}

function safeInt(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function fileSize(filePath) {
  try {
    return fs.statSync(filePath).size;
  } catch {
    return 0;
  }
}

function sqliteStoreSize(dbPath) {
  if (!dbPath) return 0;
  return ["", "-wal", "-shm"].reduce((sum, suffix) => sum + fileSize(`${dbPath}${suffix}`), 0);
}

function normalizeRuleMap(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    const cleanKey = String(key || "").trim();
    if (!cleanKey) continue;
    if (item === false || item == null) continue;
    out[cleanKey] = typeof item === "string" ? item : item === true ? new Date().toISOString() : String(item);
  }
  return out;
}

function normalizeTriageState(value = {}) {
  return {
    reviewedRules: normalizeRuleMap(value.reviewedRules || value.sigmaReviewedRules),
    falsePositiveRules: normalizeRuleMap(value.falsePositiveRules || value.sigmaFalsePositiveRules),
    taggedRules: normalizeRuleMap(value.taggedRules || value.sigmaTaggedRules),
    bookmarkedRules: normalizeRuleMap(value.bookmarkedRules || value.sigmaBookmarkedRules),
  };
}

function historyStorageSize(record) {
  if (!record) return 0;
  return sqliteStoreSize(record.resultDbPath) + fileSize(record.htmlReportPath);
}

function summarizeRecord(record) {
  if (!record) return null;
  const {
    matches,
    errors,
    warnings,
    resultDbPath,
    htmlReportPath,
    ...summary
  } = record;
  return {
    ...summary,
    matchSummaryCount: Array.isArray(matches) ? matches.length : 0,
    errorCount: Array.isArray(errors) ? errors.length : 0,
    warningCount: Array.isArray(warnings) ? warnings.length : 0,
    hasResultStore: !!resultDbPath && fs.existsSync(resultDbPath),
    hasHtmlReport: !!htmlReportPath && fs.existsSync(htmlReportPath),
    resultStoreSizeBytes: sqliteStoreSize(resultDbPath),
    historyStorageSizeBytes: historyStorageSize(record),
  };
}

function checkpointResultStore(dbPath) {
  if (!dbPath || !fs.existsSync(dbPath)) return;
  let store;
  try {
    store = SigmaResultStore.open(dbPath);
    store.db.pragma("wal_checkpoint(TRUNCATE)");
  } catch {
    // Best effort only. If a WAL file remains, copy it with the main database.
  } finally {
    try { store?.close(); } catch {}
  }
}

function copySqliteStore(sourcePath, destPath) {
  if (!sourcePath || !fs.existsSync(sourcePath)) return null;
  checkpointResultStore(sourcePath);
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  for (const suffix of ["", "-wal", "-shm"]) {
    const src = `${sourcePath}${suffix}`;
    const dst = `${destPath}${suffix}`;
    if (fs.existsSync(src)) fs.copyFileSync(src, dst);
  }
  return destPath;
}

function removeRecordFiles(recordOrId) {
  const id = typeof recordOrId === "string" ? recordOrId : recordOrId?.id;
  if (!id) return;
  const dir = path.join(getResultsDir(), path.basename(id));
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

function applyRetention(records, retentionDays = 0) {
  const days = safeInt(retentionDays, 0);
  if (days <= 0) return { kept: records, dropped: [] };
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const kept = [];
  const dropped = [];
  for (const record of records) {
    const createdAtMs = Date.parse(record.createdAt || "");
    if (Number.isFinite(createdAtMs) && createdAtMs < cutoff) dropped.push(record);
    else kept.push(record);
  }
  return { kept, dropped };
}

function saveScanHistory({ jobId, resultDbPath, htmlReport, metadata = {} } = {}) {
  ensureDirs();
  const createdAt = metadata.createdAt || new Date().toISOString();
  const id = metadata.id || createHistoryId(Date.parse(createdAt) || Date.now());
  const recordDir = path.join(getResultsDir(), id);
  const copiedDbPath = resultDbPath ? copySqliteStore(resultDbPath, path.join(recordDir, "results.sqlite")) : null;

  let htmlReportPath = null;
  if (htmlReport) {
    fs.mkdirSync(recordDir, { recursive: true });
    htmlReportPath = path.join(recordDir, "report.html");
    fs.writeFileSync(htmlReportPath, String(htmlReport), "utf8");
  }

  const stats = metadata.stats || {};
  const matches = Array.isArray(metadata.matches) ? metadata.matches : [];
  const errors = Array.isArray(metadata.errors) ? metadata.errors : [];
  const warnings = Array.isArray(metadata.warnings) ? metadata.warnings : [];
  const record = {
    id,
    jobId: jobId || metadata.jobId || null,
    createdAt,
    scanType: metadata.scanType || "tab",
    engine: metadata.engine || "IRFlow Sigma Engine",
    targetName: metadata.targetName || metadata.targetPath || "Unknown target",
    targetPath: metadata.targetPath || "",
    sourceTabId: metadata.sourceTabId || null,
    hayabusaVersion: metadata.hayabusaVersion || null,
    hayabusaRuleCount: safeInt(metadata.hayabusaRuleCount, 0),
    hayabusaRulesLastUpdate: metadata.hayabusaRulesLastUpdate || null,
    hayabusaRulesDir: metadata.hayabusaRulesDir || null,
    hayabusaRulesSnapshotHash: metadata.hayabusaRulesSnapshotHash || metadata.hayabusaRuleSnapshotHash || null,
    hayabusaRuleUpdateLog: Array.isArray(metadata.hayabusaRuleUpdateLog) ? metadata.hayabusaRuleUpdateLog : [],
    hayabusaRuleUpdateMeta: metadata.hayabusaRuleUpdateMeta || null,
    ruleLastUpdate: metadata.ruleLastUpdate || null,
    ruleSnapshotHash: metadata.ruleSnapshotHash || null,
    ruleRepoSnapshots: Array.isArray(metadata.ruleRepoSnapshots) ? metadata.ruleRepoSnapshots : [],
    ruleCompatibilityReport: metadata.ruleCompatibilityReport || metadata.ruleCompatibility || stats.ruleCompatibility || null,
    ruleUpdateLog: Array.isArray(metadata.ruleUpdateLog) ? metadata.ruleUpdateLog : [],
    cachedRuleCount: safeInt(metadata.cachedRuleCount, 0),
    customRuleCount: safeInt(metadata.customRuleCount, 0),
    commandLine: metadata.commandLine || stats.commandLine || metadata.reproducibility?.commandLine || null,
    commandArgs: Array.isArray(metadata.commandArgs) ? metadata.commandArgs : Array.isArray(metadata.reproducibility?.commandArgs) ? metadata.reproducibility.commandArgs : [],
    reproducibility: metadata.reproducibility || null,
    configFiles: Array.isArray(metadata.configFiles) ? metadata.configFiles : [],
    levels: metadata.levels || [],
    statuses: metadata.statuses || [],
    categories: metadata.categories || null,
    options: metadata.options || {},
    matchedRules: safeInt(stats.matchedRules, matches.length),
    totalMatches: safeInt(stats.totalMatches, metadata.eventRowCount || 0),
    eventRowCount: safeInt(metadata.eventRowCount, safeInt(stats.totalMatches, 0)),
    totalRules: safeInt(stats.totalRules, 0),
    rowsScanned: safeInt(stats.rowsScanned, 0),
    evtxFiles: safeInt(stats.evtxFiles, metadata.evtxFiles?.length || 0),
    evtxTotalRows: safeInt(stats.evtxTotalRows, 0),
    evtxTotalBytes: safeInt(stats.evtxTotalBytes, metadata.evtxTotalBytes || 0),
    runtimeMs: safeInt(stats.runtimeMs, metadata.runtimeMs || 0),
    triageState: normalizeTriageState(metadata.triageState),
    triageAggregates: metadata.triageAggregates || null,
    resultDbPath: copiedDbPath,
    htmlReportPath,
    hasHtmlReport: !!htmlReportPath,
    matches,
    stats,
    errors,
    warnings,
  };

  const prior = readHistoryFile().filter((r) => r.id !== id);
  prior.unshift(record);
  let kept = prior
    .sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0))
    .slice(0, MAX_HISTORY_RECORDS);
  const retentionResult = applyRetention(kept, readSettingsFile().retentionDays);
  kept = retentionResult.kept;
  const droppedById = new Map([
    ...prior.filter((r) => !kept.some((k) => k.id === r.id)),
    ...retentionResult.dropped,
  ].map((r) => [r.id, r]));
  const dropped = [...droppedById.values()];
  for (const droppedRecord of dropped) removeRecordFiles(droppedRecord);
  writeHistoryFile(kept);
  return summarizeRecord(record);
}

function listScanHistory() {
  return readHistoryFile()
    .sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0))
    .map(summarizeRecord);
}

function getScanHistory(id) {
  if (!id) return null;
  return readHistoryFile().find((r) => r.id === id) || null;
}

function updateScanTriage(id, triageState = {}) {
  if (!id) return { updated: false, error: "Scan history record not found" };
  const records = readHistoryFile();
  const idx = records.findIndex((r) => r.id === id);
  if (idx < 0) return { updated: false, error: "Scan history record not found" };
  records[idx] = {
    ...records[idx],
    triageState: normalizeTriageState(triageState),
    triageUpdatedAt: new Date().toISOString(),
  };
  writeHistoryFile(records);
  return { updated: true, id, triageState: records[idx].triageState, triageUpdatedAt: records[idx].triageUpdatedAt };
}

function deleteScanHistory(id) {
  const records = readHistoryFile();
  const target = records.find((r) => r.id === id);
  if (!target) return { deleted: false };
  removeRecordFiles(target);
  writeHistoryFile(records.filter((r) => r.id !== id));
  return { deleted: true, id };
}

function clearScanHistory() {
  const count = readHistoryFile().length;
  try { fs.rmSync(getResultsDir(), { recursive: true, force: true }); } catch {}
  ensureDirs();
  writeHistoryFile([]);
  return { cleared: count };
}

function pruneScanHistory({ retentionDays } = {}) {
  const settings = readSettingsFile();
  const days = retentionDays == null ? settings.retentionDays : safeInt(retentionDays, settings.retentionDays);
  const records = readHistoryFile();
  const { kept, dropped } = applyRetention(records, days);
  for (const record of dropped) removeRecordFiles(record);
  writeHistoryFile(kept);
  return { deleted: dropped.length, kept: kept.length, retentionDays: days };
}

function readHtmlReport(id) {
  const record = getScanHistory(id);
  if (!record?.htmlReportPath || !fs.existsSync(record.htmlReportPath)) return null;
  return fs.readFileSync(record.htmlReportPath, "utf8");
}

function copyIfExists(sourcePath, destPath) {
  if (!sourcePath || !fs.existsSync(sourcePath)) return null;
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  fs.copyFileSync(sourcePath, destPath);
  return destPath;
}

function packageName(record) {
  const stamp = String(record.createdAt || new Date().toISOString()).slice(0, 19).replace(/[:T]/g, "-");
  const target = String(record.targetName || record.scanType || "scan")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || "scan";
  return `irflow-scan-${stamp}-${target}-${record.id}`;
}

async function exportScanPackage(id, destinationDir) {
  const record = getScanHistory(id);
  if (!record) return { error: "Scan history record not found" };
  if (!destinationDir) return { error: "No destination directory specified" };
  fs.mkdirSync(destinationDir, { recursive: true });
  const outDir = path.join(destinationDir, packageName(record));
  fs.mkdirSync(outDir, { recursive: true });

  const summary = summarizeRecord(record);
  const metadata = {
    ...record,
    resultDbPath: record.resultDbPath ? "results.sqlite" : null,
    htmlReportPath: record.htmlReportPath ? "report.html" : null,
    resultStoreSizeBytes: summary.resultStoreSizeBytes,
    historyStorageSizeBytes: summary.historyStorageSizeBytes,
  };
  fs.writeFileSync(path.join(outDir, "metadata.json"), JSON.stringify(metadata, null, 2), "utf8");
  if (record.ruleUpdateLog?.length) {
    fs.writeFileSync(path.join(outDir, "rule-update.log"), record.ruleUpdateLog.join("\n") + "\n", "utf8");
  }
  if (record.hayabusaRuleUpdateLog?.length) {
    fs.writeFileSync(path.join(outDir, "hayabusa-rule-update.log"), record.hayabusaRuleUpdateLog.join("\n") + "\n", "utf8");
  }
  if (record.commandLine) {
    fs.writeFileSync(path.join(outDir, "scan-command.txt"), `${record.commandLine}\n`, "utf8");
  }
  if (record.ruleCompatibilityReport) {
    fs.writeFileSync(path.join(outDir, "rule-compatibility.json"), JSON.stringify(record.ruleCompatibilityReport, null, 2), "utf8");
  }
  if (Array.isArray(record.configFiles) && record.configFiles.length > 0) {
    const configDir = path.join(outDir, "config");
    fs.mkdirSync(configDir, { recursive: true });
    const copied = [];
    for (const cfg of record.configFiles) {
      if (!cfg?.path || !fs.existsSync(cfg.path)) continue;
      const safeName = String(cfg.relativePath || path.basename(cfg.path)).replace(/[/\\]+/g, "__");
      const dest = path.join(configDir, safeName);
      copyIfExists(cfg.path, dest);
      copied.push({ ...cfg, packagedAs: path.join("config", safeName) });
    }
    if (copied.length > 0) {
      fs.writeFileSync(path.join(configDir, "manifest.json"), JSON.stringify(copied, null, 2), "utf8");
    }
  }

  if (record.resultDbPath && fs.existsSync(record.resultDbPath)) {
    checkpointResultStore(record.resultDbPath);
    copyIfExists(record.resultDbPath, path.join(outDir, "results.sqlite"));
    copyIfExists(`${record.resultDbPath}-wal`, path.join(outDir, "results.sqlite-wal"));
    copyIfExists(`${record.resultDbPath}-shm`, path.join(outDir, "results.sqlite-shm"));
    let store;
    try {
      store = SigmaResultStore.open(record.resultDbPath);
      await store.exportCsv(path.join(outDir, "detections.csv"));
      await store.exportJson(path.join(outDir, "detections.json"));
    } finally {
      try { store?.close(); } catch {}
    }
  }

  copyIfExists(record.htmlReportPath, path.join(outDir, "report.html"));
  fs.writeFileSync(path.join(outDir, "README.txt"), [
    "IRFlow detection scan package",
    "",
    `Scan ID: ${record.id}`,
    `Target: ${record.targetName || record.targetPath || "Unknown"}`,
    `Created: ${record.createdAt || ""}`,
    `Engine: ${record.engine || ""}`,
    "",
    "Files:",
    "- metadata.json: scan metadata, matched rule summaries, options, and stats",
    "- scan-command.txt: exact scan command when an external engine was used",
    "- rule-compatibility.json: JS Sigma compatibility report when available",
    "- rule-update.log: captured rule update log when available",
    "- hayabusa-rule-update.log: captured Hayabusa rule update log when available",
    "- config/: scan config files copied when available",
    "- detections.csv: full detection rows when a result store exists",
    "- detections.json: full detection rows when a result store exists",
    "- results.sqlite: original persisted detection result store",
    "- report.html: Hayabusa report when available",
    "",
  ].join("\n"), "utf8");

  let bytes = 0;
  for (const entry of fs.readdirSync(outDir)) bytes += fileSize(path.join(outDir, entry));
  return { exported: true, path: outDir, bytes };
}

module.exports = {
  getHistoryDir,
  getHistoryFile,
  getSettingsFile,
  createHistoryId,
  saveScanHistory,
  listScanHistory,
  getScanHistory,
  updateScanTriage,
  deleteScanHistory,
  clearScanHistory,
  pruneScanHistory,
  readHtmlReport,
  summarizeRecord,
  normalizeTriageState,
  getScanHistorySettings: readSettingsFile,
  saveScanHistorySettings: writeSettingsFile,
  exportScanPackage,
};
