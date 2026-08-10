/**
 * sigma/result-store.js — durable storage for Sigma/Hayabusa scan hits.
 *
 * Scan result sets can be much larger than is safe to keep in memory or pass
 * through IPC. This store keeps the full matched timeline in a temporary SQLite
 * database while the renderer receives only summaries and preview rows.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const Database = require("better-sqlite3");

const DEFAULT_PRIORITY_HEADERS = [
  "Timestamp", "Computer", "Channel", "EventID", "Level", "RuleID", "RuleTitle",
  "User", "MITRE", "Image", "CommandLine", "Cmdline", "Proc", "ParentImage",
  "ParentCommandLine", "TargetFilename", "TargetObject", "ServiceName", "Hashes",
  "LogonType", "IpAddress", "WorkstationName", "DestinationIp", "DestinationPort",
  "SourcePort", "Details", "ExtraFieldInfo", "_SourceFile", "RecordID", "RuleFile",
  "Tags", "ScriptBlockText", "ShareName", "MapDescription", "RemoteHost",
  "Description", "Category", "Author", "SourceTabId", "SourceRowId",
];

function createTempResultPath(prefix = "tle-sigma-results") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}-`));
  return path.join(dir, "results.sqlite");
}

function unlinkSqliteFiles(dbPath) {
  if (!dbPath) return;
  for (const suffix of ["", "-wal", "-shm"]) {
    try { if (fs.existsSync(`${dbPath}${suffix}`)) fs.unlinkSync(`${dbPath}${suffix}`); } catch {}
  }
  try {
    const dir = path.dirname(dbPath);
    if (path.basename(dbPath) === "results.sqlite" && fs.existsSync(dir)) fs.rmdirSync(dir);
  } catch {}
}

function orderedHeaders(headers, priority = DEFAULT_PRIORITY_HEADERS) {
  const set = new Set(headers || []);
  return [
    ...priority.filter((h) => set.has(h)),
    ...[...set].filter((h) => !priority.includes(h) && !h.startsWith("_")).sort(),
    ...[...set].filter((h) => !priority.includes(h) && h.startsWith("_")).sort(),
  ];
}

class SigmaResultStore {
  constructor({ dbPath = createTempResultPath(), create = true } = {}) {
    this.dbPath = dbPath;
    this.db = new Database(dbPath);
    this.headers = new Set();
    this.rowCount = 0;
    this.closed = false;

    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");
    this.db.pragma("temp_store = FILE");
    this.db.pragma("cache_size = -65536");

    if (create) this._init();
    else this._loadMeta();

    this.insertStmt = this.db.prepare(`
      INSERT INTO sigma_results (
        source_tab_id, source_row_id, timestamp, computer, channel, event_id,
        level, rule_id, rule_title, mitre, payload
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    this.insertMany = this.db.transaction((rows) => {
      for (const row of rows) this._insertOne(row);
    });
  }

  static createTemp() {
    return new SigmaResultStore({ dbPath: createTempResultPath(), create: true });
  }

  static open(dbPath) {
    return new SigmaResultStore({ dbPath, create: false });
  }

  static destroy(dbPath) {
    unlinkSqliteFiles(dbPath);
  }

  _init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sigma_results (
        id INTEGER PRIMARY KEY,
        source_tab_id TEXT,
        source_row_id INTEGER,
        timestamp TEXT,
        computer TEXT,
        channel TEXT,
        event_id TEXT,
        level TEXT,
        rule_id TEXT,
        rule_title TEXT,
        mitre TEXT,
        payload TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sigma_rule_title ON sigma_results(rule_title);
      CREATE INDEX IF NOT EXISTS idx_sigma_rule_id ON sigma_results(rule_id);
      CREATE INDEX IF NOT EXISTS idx_sigma_timestamp ON sigma_results(timestamp);
      CREATE INDEX IF NOT EXISTS idx_sigma_level ON sigma_results(level);
      CREATE INDEX IF NOT EXISTS idx_sigma_computer ON sigma_results(computer);
      CREATE INDEX IF NOT EXISTS idx_sigma_event_id ON sigma_results(event_id);
      CREATE INDEX IF NOT EXISTS idx_sigma_source_row ON sigma_results(source_tab_id, source_row_id);
      CREATE TABLE IF NOT EXISTS sigma_meta (key TEXT PRIMARY KEY, value TEXT);
    `);
  }

  _loadMeta() {
    try {
      const rows = this.db.prepare("SELECT key, value FROM sigma_meta").all();
      const meta = Object.fromEntries(rows.map((r) => [r.key, r.value]));
      this.rowCount = Number(meta.rowCount || 0);
      const headers = JSON.parse(meta.headers || "[]");
      this.headers = new Set(headers);
    } catch {
      this.rowCount = 0;
      this.headers = new Set();
    }
  }

  _insertOne(row) {
    if (!row || typeof row !== "object") return;
    for (const key of Object.keys(row)) this.headers.add(key);
    this.insertStmt.run(
      row.SourceTabId || row.sourceTabId || "",
      Number(row.SourceRowId || row.sourceRowId || 0) || null,
      row.Timestamp || "",
      row.Computer || "",
      row.Channel || "",
      String(row.EventID ?? row.EventId ?? ""),
      row.Level || "",
      row.RuleID || row.ruleId || "",
      row.RuleTitle || row.ruleTitle || "",
      row.MITRE || "",
      JSON.stringify(row),
    );
    this.rowCount++;
  }

  addRow(row) {
    this._insertOne(row);
  }

  addRows(rows) {
    if (!Array.isArray(rows) || rows.length === 0) return;
    this.insertMany(rows);
  }

  finalize(extraMeta = {}) {
    const headers = orderedHeaders([...this.headers]);
    const writeMeta = this.db.prepare("INSERT OR REPLACE INTO sigma_meta (key, value) VALUES (?, ?)");
    const tx = this.db.transaction(() => {
      writeMeta.run("headers", JSON.stringify(headers));
      writeMeta.run("rowCount", String(this.rowCount));
      for (const [key, value] of Object.entries(extraMeta || {})) {
        writeMeta.run(key, typeof value === "string" ? value : JSON.stringify(value));
      }
    });
    tx();
    return { dbPath: this.dbPath, rowCount: this.rowCount, headers };
  }

  getHeaders() {
    if (!this.headers.size) this._loadMeta();
    return orderedHeaders([...this.headers]);
  }

  getPreview(limit = 2000) {
    return this.db
      .prepare("SELECT payload FROM sigma_results ORDER BY timestamp, id LIMIT ?")
      .all(limit)
      .map((r) => JSON.parse(r.payload));
  }

  *iterateRows() {
    for (const r of this.db.prepare("SELECT payload FROM sigma_results ORDER BY timestamp, id").iterate()) {
      yield JSON.parse(r.payload);
    }
  }

  getSourceRowsForRule({ ruleId, ruleTitle } = {}) {
    const clauses = [];
    const params = [];
    if (ruleId) { clauses.push("rule_id = ?"); params.push(ruleId); }
    if (ruleTitle) { clauses.push("rule_title = ?"); params.push(ruleTitle); }
    if (clauses.length === 0) return [];
    return this.db.prepare(`
      SELECT DISTINCT source_tab_id AS tabId, source_row_id AS rowId
      FROM sigma_results
      WHERE source_row_id IS NOT NULL AND source_row_id > 0
        AND (${clauses.join(" OR ")})
      ORDER BY source_tab_id, source_row_id
    `).all(...params);
  }

  getRowsForRule({ ruleId, ruleTitle } = {}, limit = 100000) {
    const clauses = [];
    const params = [];
    if (ruleId) { clauses.push("rule_id = ?"); params.push(ruleId); }
    if (ruleTitle) { clauses.push("rule_title = ?"); params.push(ruleTitle); }
    if (clauses.length === 0) return [];
    params.push(Math.max(1, Math.min(Number(limit) || 100000, 500000)));
    return this.db.prepare(`
      SELECT payload
      FROM sigma_results
      WHERE ${clauses.join(" OR ")}
      ORDER BY timestamp, id
      LIMIT ?
    `).all(...params).map((r) => JSON.parse(r.payload));
  }

  getTriageAggregates({ limit = 20 } = {}) {
    const add = (map, value, weight = 1) => {
      const key = String(value ?? "").trim();
      if (!key || key === "-") return;
      map.set(key, (map.get(key) || 0) + weight);
    };
    const first = (row, keys) => {
      for (const key of keys) {
        const value = String(row?.[key] ?? "").trim();
        if (value) return value;
      }
      return "";
    };
    const entriesDesc = (map, max = limit) => [...map.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, max)
      .map(([value, count]) => ({ value, count }));
    const entriesRare = (map, max = limit) => [...map.entries()]
      .filter(([, count]) => count <= 1)
      .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]))
      .slice(0, max)
      .map(([value, count]) => ({ value, count }));
    const parseList = (value) => {
      if (Array.isArray(value)) return value.flatMap(parseList);
      return String(value ?? "").split(/[,\s;]+/).map((v) => v.trim()).filter(Boolean);
    };
    const hostCounts = new Map();
    const userCounts = new Map();
    const processCounts = new Map();
    const ruleCounts = new Map();
    const techniqueCounts = new Map();
    const tacticCounts = new Map();
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    let firstSeen = "";
    let lastSeen = "";
    let totalRows = 0;

    for (const row of this.iterateRows()) {
      totalRows++;
      const ts = first(row, ["Timestamp", "datetime", "TimeCreated", "UtcTime"]);
      if (ts) {
        if (!firstSeen || ts < firstSeen) firstSeen = ts;
        if (!lastSeen || ts > lastSeen) lastSeen = ts;
      }
      add(hostCounts, first(row, ["Computer", "Hostname", "Host", "ComputerName"]));
      add(userCounts, first(row, ["User", "TargetUserName", "SubjectUserName", "AccountName", "UserName"]));
      add(processCounts, first(row, ["Image", "ProcessName", "Proc", "CommandLine", "Cmdline"]));
      const ruleKey = first(row, ["RuleTitle", "SigmaRuleTitle", "RuleID", "SigmaRuleId"]);
      add(ruleCounts, ruleKey);
      const level = String(row.Level || "").toLowerCase();
      if (Object.prototype.hasOwnProperty.call(severityCounts, level)) severityCounts[level]++;
      for (const item of parseList(row.MITRE || row.MitreTags || row.MitreTactics)) {
        if (/^t\d{4}/i.test(item)) add(techniqueCounts, item.toUpperCase());
        else add(tacticCounts, item);
      }
    }

    return {
      source: "result-store",
      totalRows,
      firstSeen,
      lastSeen,
      affectedHosts: entriesDesc(hostCounts, limit),
      rareHosts: entriesRare(hostCounts, limit),
      rareUsers: entriesRare(userCounts, limit),
      rareProcesses: entriesRare(processCounts, limit),
      topRules: entriesDesc(ruleCounts, limit),
      mitreTechniques: entriesDesc(techniqueCounts, limit),
      mitreTactics: entriesDesc(tacticCounts, limit),
      severityCounts,
    };
  }

  exportCsv(filePath) {
    const headers = this.getHeaders();
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const ws = fs.createWriteStream(filePath);
    ws.write(headers.join(",") + "\n");
    for (const row of this.iterateRows()) {
      ws.write(headers.map((h) => esc(row[h])).join(",") + "\n");
    }
    return new Promise((resolve, reject) => {
      ws.on("error", reject);
      ws.end(() => resolve({ rowCount: this.rowCount, headers }));
    });
  }

  exportJson(filePath) {
    const ws = fs.createWriteStream(filePath);
    ws.write('{"eventRows":[\n');
    let first = true;
    let count = 0;
    for (const row of this.iterateRows()) {
      if (!first) ws.write(",\n");
      first = false;
      ws.write(JSON.stringify(row));
      count++;
    }
    ws.write("\n]}\n");
    return new Promise((resolve, reject) => {
      ws.on("error", reject);
      ws.end(() => resolve({ rowCount: count }));
    });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    try { this.db.close(); } catch {}
  }
}

module.exports = {
  SigmaResultStore,
  createTempResultPath,
  orderedHeaders,
  DEFAULT_PRIORITY_HEADERS,
};
