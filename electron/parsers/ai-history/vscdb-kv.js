/**
 * vscdb-kv.js — read Cursor / VS Code state.vscdb and store.db key-value SQLite stores.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");

function loadSqlite() {
  try {
    return require("better-sqlite3");
  } catch (e) {
    throw new Error("SQLite support unavailable (better-sqlite3 not loaded).");
  }
}

function openVscdbReadOnly(dbPath) {
  const Database = loadSqlite();
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  return db;
}

function listTables(db) {
  const rows = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
  ).all();
  return rows.map((r) => r.name);
}

function kvTableNames(db) {
  const names = listTables(db);
  const out = [];
  if (names.includes("cursorDiskKV")) out.push("cursorDiskKV");
  if (names.includes("ItemTable")) out.push("ItemTable");
  return out;
}

// SQLite BLOB/TEXT can hold ~1GB. A crafted state.vscdb value would force a huge string alloc
// + full JSON.parse and OOM the worker, so refuse oversized values. 32MB is far above any
// legitimate chat/composer KV blob.
const MAX_KV_VALUE_BYTES = 32 * 1024 * 1024;
/** Cap bubble rows loaded per composer — very long chats can hold 10k+ KV entries. */
const MAX_BUBBLES_PER_COMPOSER = 4000;

function parseKvValue(raw) {
  if (raw == null) return null;
  if (Buffer.isBuffer(raw)) {
    if (raw.length > MAX_KV_VALUE_BYTES) {
      dbg("AIHIST", "skip oversized vscdb value", { bytes: raw.length });
      return null;
    }
    const text = raw.toString("utf8").replace(/^\uFEFF/, "").trim();
    if (!text) return null;
    try { return JSON.parse(text); } catch { return text; }
  }
  if (typeof raw === "string") {
    if (raw.length > MAX_KV_VALUE_BYTES) {
      dbg("AIHIST", "skip oversized vscdb value", { chars: raw.length });
      return null;
    }
    const text = raw.trim();
    if (!text) return null;
    try { return JSON.parse(text); } catch { return text; }
  }
  return raw;
}

/**
 * @param {import("better-sqlite3").Database} db
 * @param {string} table
 * @param {string} [keyLike] SQL LIKE pattern (no % added)
 */
function queryKvByKeyLike(db, table, keyLike) {
  const pattern = keyLike.includes("%") ? keyLike : `${keyLike}%`;
  return db.prepare(`SELECT key, value FROM ${table} WHERE key LIKE ? ORDER BY rowid ASC`)
    .all(pattern);
}

function queryKvByKey(db, table, key) {
  const row = db.prepare(`SELECT key, value FROM ${table} WHERE key = ?`).get(key);
  return row || null;
}

/**
 * Load composer + bubble KV rows in one pass (avoids N+1 LIKE queries per bubble).
 * @returns {{ composers: Map<string, object>, bubbles: Map<string, object> }}
 */
function loadCursorComposerKv(db) {
  const composers = new Map();
  const bubbles = new Map();
  const tables = kvTableNames(db);
  if (!tables.includes("cursorDiskKV")) return { composers, bubbles };

  const rows = db.prepare(
    `SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%' OR key LIKE 'bubbleId:%' ORDER BY rowid ASC`,
  ).all();

  for (const { key, value } of rows) {
    if (key.startsWith("composerData:")) {
      const composerId = key.slice("composerData:".length);
      if (composerId) composers.set(composerId, parseKvValue(value));
    } else if (key.startsWith("bubbleId:")) {
      bubbles.set(key, parseKvValue(value));
    }
  }
  return { composers, bubbles };
}

/** List composer metadata rows without loading bubble payloads (memory-safe). */
function listComposerDataRows(db) {
  const tables = kvTableNames(db);
  if (!tables.includes("cursorDiskKV")) return [];
  return db.prepare(
    "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%' ORDER BY rowid ASC",
  ).all();
}

/** Load bubble JSON for one composer session (scoped LIKE — avoids loading the whole KV table). */
function loadBubblesForComposer(db, composerId) {
  const tables = kvTableNames(db);
  if (!tables.includes("cursorDiskKV") || !composerId) return [];
  const rows = db.prepare(
    "SELECT key, value FROM cursorDiskKV WHERE key LIKE ? ORDER BY rowid ASC",
  ).all(`bubbleId:${composerId}:%`);
  const out = [];
  for (const { value } of rows) {
    if (out.length >= MAX_BUBBLES_PER_COMPOSER) break;
    const bubble = parseKvValue(value);
    if (bubble && typeof bubble === "object") out.push(bubble);
  }
  return out;
}

/**
 * Load one composer's bubbles as a Map keyed by the FULL KV key (`bubbleId:<composerId>:<bubbleId>`),
 * via ONE scoped LIKE query. Lets the header-ordered path look bubbles up by key instead of issuing a
 * separate `SELECT … WHERE key = ?` per header (the old N+1 — 100+ round-trips for a long session).
 */
function loadBubbleMapForComposer(db, composerId) {
  const map = new Map();
  const tables = kvTableNames(db);
  if (!tables.includes("cursorDiskKV") || !composerId) return map;
  const rows = db.prepare(
    "SELECT key, value FROM cursorDiskKV WHERE key LIKE ? ORDER BY rowid ASC",
  ).all(`bubbleId:${composerId}:%`);
  for (const { key, value } of rows) {
    if (map.size >= MAX_BUBBLES_PER_COMPOSER) break;
    const bubble = parseKvValue(value);
    if (bubble && typeof bubble === "object") map.set(key, bubble);
  }
  return map;
}

function findVscdbFilesUnder(rootDir, opts = {}) {
  const maxDepth = opts.maxDepth ?? 14;
  const maxFiles = opts.maxFiles ?? 32;
  const names = new Set(["state.vscdb", "store.db"]);
  const out = [];
  const stack = [{ d: rootDir, depth: 0 }];

  while (stack.length && out.length < maxFiles) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!e.isSymbolicLink() && depth < maxDepth) stack.push({ d: full, depth: depth + 1 });
        continue;
      }
      if (!e.isFile() || !names.has(e.name)) continue;
      out.push(full);
      if (out.length >= maxFiles) break;
    }
  }
  return out;
}

function readWorkspaceJsonMap(cursorUserDir) {
  const map = new Map();
  const wsRoot = path.join(cursorUserDir, "workspaceStorage");
  if (!fs.existsSync(wsRoot)) return map;
  let entries;
  try { entries = fs.readdirSync(wsRoot, { withFileTypes: true }); } catch { return map; }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const wj = path.join(wsRoot, e.name, "workspace.json");
    if (!fs.existsSync(wj)) continue;
    try {
      const data = JSON.parse(fs.readFileSync(wj, "utf8"));
      const folder = data.folder || data.workspace || "";
      if (folder) map.set(e.name, String(folder).replace(/^file:\/\//, ""));
    } catch { /* ignore */ }
  }
  return map;
}

function safeCloseDb(db) {
  if (!db) return;
  try { db.close(); } catch (e) {
    dbg("AIHIST", "vscdb close failed", { err: e.message });
  }
}

module.exports = {
  openVscdbReadOnly,
  listTables,
  kvTableNames,
  parseKvValue,
  queryKvByKeyLike,
  queryKvByKey,
  loadCursorComposerKv,
  listComposerDataRows,
  loadBubblesForComposer,
  loadBubbleMapForComposer,
  findVscdbFilesUnder,
  readWorkspaceJsonMap,
  safeCloseDb,
  loadSqlite,
};
