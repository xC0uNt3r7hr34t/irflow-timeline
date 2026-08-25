/**
 * sqlite.js — Generic SQLite table import (non-Plaso).
 *
 * Magic-byte SQLite files (.sqlite / .db / .sqlite3) that are not Plaso
 * databases are imported one table at a time. Multi-table files go through
 * the same picker UX as multi-sheet workbooks.
 */

const fs = require("fs");
const { dbg } = require("../logger");

const SQLITE_MAGIC = Buffer.from("SQLite format 3\0");
const BATCH_SIZE_DEFAULT = 50000;
const BATCH_SIZE_LARGE = 100000;
const BATCH_SIZE_MAX_BYTES = 80 * 1024 * 1024;
const LARGE_DB_BYTES = 100 * 1024 * 1024; // skip exact COUNT(*) above this
const LARGE_FILE_BYTES = 5 * 1024 * 1024 * 1024;

function isSqliteFile(filePath) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    fs.closeSync(fd);
    return buf.equals(SQLITE_MAGIC);
  } catch {
    return false;
  }
}

function quoteSqliteIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

function openSqliteReadonly(filePath) {
  const Database = require("better-sqlite3");
  const sqliteDb = new Database(filePath, { readonly: true, fileMustExist: true });
  try { sqliteDb.pragma("query_only = ON"); } catch {}
  try { sqliteDb.pragma("mmap_size = 268435456"); } catch {}
  try { sqliteDb.pragma("cache_size = -65536"); } catch {}
  return sqliteDb;
}

function coerceSqliteValue(val) {
  if (val == null) return "";
  if (Buffer.isBuffer(val)) return val.length ? `0x${val.toString("hex")}` : "";
  if (typeof val === "bigint") return val.toString();
  if (typeof val === "object") {
    try { return JSON.stringify(val); } catch { return String(val); }
  }
  return String(val);
}

/**
 * Fast row-count estimate for large tables. COUNT(*) on multi-GB tables can take
 * minutes; MAX(rowid) is usually instant when rowid is the primary key.
 */
function estimateTableRowCount(sqliteDb, tableName, useFastEstimate) {
  const quoted = quoteSqliteIdent(tableName);
  if (!useFastEstimate) {
    try {
      return sqliteDb.prepare(`SELECT COUNT(*) AS cnt FROM ${quoted}`).get()?.cnt || 0;
    } catch (e) {
      dbg("SQLITE", "estimateTableRowCount exact failed", { table: tableName, error: e.message });
      return null;
    }
  }
  try {
    const maxRow = sqliteDb.prepare(`SELECT MAX(rowid) AS mx FROM ${quoted}`).get()?.mx;
    if (Number.isFinite(maxRow) && maxRow > 0) return maxRow;
  } catch {}
  try {
    return sqliteDb.prepare(`SELECT COUNT(*) AS cnt FROM ${quoted}`).get()?.cnt || 0;
  } catch (e) {
    dbg("SQLITE", "estimateTableRowCount failed", { table: tableName, error: e.message });
    return null;
  }
}

function listSqliteTables(filePath, fileSizeHint = 0, options = {}) {
  const { rowCounts = true } = options;
  dbg("SQLITE", "listSqliteTables start", { filePath, rowCounts });
  let fileSize = fileSizeHint;
  if (!fileSize) {
    try { fileSize = fs.statSync(filePath).size; } catch {}
  }
  const useFastEstimate = fileSize > LARGE_DB_BYTES;

  let sqliteDb;
  try {
    sqliteDb = openSqliteReadonly(filePath);
    const rows = sqliteDb.prepare(
      `SELECT name, sql FROM sqlite_master
       WHERE type = 'table'
         AND name NOT LIKE 'sqlite_%'
       ORDER BY name`
    ).all();
    const tables = [];
    for (const row of rows) {
      if (row.sql && /VIRTUAL/i.test(row.sql)) continue;
      if (!rowCounts) {
        tables.push({ name: row.name, rowCount: 0, rowCountEstimate: false });
        continue;
      }
      const rowCount = estimateTableRowCount(sqliteDb, row.name, useFastEstimate);
      if (rowCount == null) continue;
      tables.push({
        name: row.name,
        rowCount,
        rowCountEstimate: useFastEstimate,
      });
    }
    dbg("SQLITE", "listSqliteTables done", { tableCount: tables.length, rowCounts, useFastEstimate });
    return tables;
  } finally {
    try { sqliteDb?.close(); } catch {}
  }
}

async function parseSqliteTable(filePath, tabId, db, onProgress, tableName, fileSizeHint = 0) {
  dbg("SQLITE", "parseSqliteTable start", { filePath, tabId, tableName });
  if (!tableName) throw new Error("SQLite table name required");

  let fileSize = fileSizeHint;
  if (!fileSize) {
    try { fileSize = fs.statSync(filePath).size; } catch {}
  }
  const isLargeFile = fileSize > LARGE_FILE_BYTES;
  const useFastEstimate = fileSize > LARGE_DB_BYTES;

  let sqliteDb;
  try {
    sqliteDb = openSqliteReadonly(filePath);
    const quoted = quoteSqliteIdent(tableName);
    const colInfo = sqliteDb.pragma(`table_info(${quoted})`);
    if (!colInfo.length) throw new Error(`Table has no columns: ${tableName}`);

    const headers = colInfo.map((c) => c.name);
    const colCount = headers.length;
    let totalRows = estimateTableRowCount(sqliteDb, tableName, useFastEstimate) ?? 0;
    if (!useFastEstimate) {
      // Small DBs: exact count is cheap and improves progress accuracy.
      totalRows = estimateTableRowCount(sqliteDb, tableName, false) ?? totalRows;
    }
    db.createTab(tabId, headers);

    const defaultBatch = isLargeFile ? BATCH_SIZE_LARGE : BATCH_SIZE_DEFAULT;
    const batchSize = Math.max(
      2000,
      Math.min(defaultBatch, Math.floor(BATCH_SIZE_MAX_BYTES / Math.max(colCount * 64, 64)))
    );
    let batch = [];
    let rowCount = 0;
    let lastProgress = 0;
    const stmt = sqliteDb.prepare(`SELECT * FROM ${quoted}`);

    const reportProgress = (force = false) => {
      if (!onProgress) return;
      if (!force && rowCount - lastProgress < 10000) return;
      lastProgress = rowCount;
      const bytesRead = totalRows > 0 && fileSize > 0
        ? Math.min(fileSize, Math.round((rowCount / totalRows) * fileSize))
        : rowCount;
      onProgress(rowCount, bytesRead, fileSize || totalRows, {
        phase: "parsing",
        statusDetail: isLargeFile ? `Importing SQLite table (${rowCount.toLocaleString()} rows)…` : "",
      });
    };

    for (const row of stmt.iterate()) {
      const values = new Array(colCount);
      for (let i = 0; i < colCount; i++) {
        values[i] = coerceSqliteValue(row[headers[i]]);
      }
      batch.push(values);
      rowCount++;
      if (batch.length >= batchSize) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
        reportProgress();
      }
    }
    if (batch.length) db.insertBatchArrays(tabId, batch);
    reportProgress(true);
    const result = db.finalizeImport(tabId);
    dbg("SQLITE", "parseSqliteTable done", { tableName, rowCount: result.rowCount });
    return {
      headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
      sourceFormat: "sqlite",
      isLargeFile,
    };
  } finally {
    try { sqliteDb?.close(); } catch {}
  }
}

module.exports = {
  isSqliteFile,
  listSqliteTables,
  parseSqliteTable,
  LARGE_DB_BYTES,
  LARGE_FILE_BYTES,
};
