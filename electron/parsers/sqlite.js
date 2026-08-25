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
const BATCH_SIZE_MAX_BYTES = 80 * 1024 * 1024;

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

function listSqliteTables(filePath) {
  dbg("SQLITE", "listSqliteTables start", { filePath });
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
      const quoted = quoteSqliteIdent(row.name);
      let rowCount = 0;
      try {
        rowCount = sqliteDb.prepare(`SELECT COUNT(*) AS cnt FROM ${quoted}`).get()?.cnt || 0;
      } catch (e) {
        dbg("SQLITE", "listSqliteTables count failed", { table: row.name, error: e.message });
        continue;
      }
      tables.push({ name: row.name, rowCount });
    }
    dbg("SQLITE", "listSqliteTables done", { tableCount: tables.length });
    return tables;
  } finally {
    try { sqliteDb?.close(); } catch {}
  }
}

async function parseSqliteTable(filePath, tabId, db, onProgress, tableName) {
  dbg("SQLITE", "parseSqliteTable start", { filePath, tabId, tableName });
  if (!tableName) throw new Error("SQLite table name required");

  const tables = listSqliteTables(filePath);
  const tableInfo = tables.find((t) => t.name === tableName);
  if (!tableInfo) throw new Error(`Table not found: ${tableName}`);

  let sqliteDb;
  try {
    sqliteDb = openSqliteReadonly(filePath);
    const quoted = quoteSqliteIdent(tableName);
    const colInfo = sqliteDb.pragma(`table_info(${quoted})`);
    if (!colInfo.length) throw new Error(`Table has no columns: ${tableName}`);

    const headers = colInfo.map((c) => c.name);
    const colCount = headers.length;
    const totalRows = tableInfo.rowCount;
    db.createTab(tabId, headers);

    const batchSize = Math.max(
      2000,
      Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / Math.max(colCount * 64, 64)))
    );
    let batch = [];
    let rowCount = 0;
    let lastProgress = 0;
    const stmt = sqliteDb.prepare(`SELECT * FROM ${quoted}`);

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
        if (rowCount - lastProgress >= 10000) {
          lastProgress = rowCount;
          if (onProgress) onProgress(rowCount, rowCount, totalRows);
        }
      }
    }
    if (batch.length) db.insertBatchArrays(tabId, batch);
    if (onProgress) onProgress(rowCount, totalRows, totalRows);
    const result = db.finalizeImport(tabId);
    dbg("SQLITE", "parseSqliteTable done", { tableName, rowCount: result.rowCount });
    return {
      headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
      sourceFormat: "sqlite",
    };
  } finally {
    try { sqliteDb?.close(); } catch {}
  }
}

module.exports = {
  isSqliteFile,
  listSqliteTables,
  parseSqliteTable,
};
