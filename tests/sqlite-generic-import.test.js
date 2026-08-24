const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  isSqliteFile,
  listSqliteTables,
  parseSqliteTable,
} = require("../electron/parsers/sqlite");
const { makeImportQueueKey } = require("../electron/utils/import-queue");

function skipSqlite(t, err) {
  if (/ERR_DLOPEN_FAILED|better-sqlite3|NODE_MODULE_VERSION/.test(String(err?.message || err))) {
    t.skip("better-sqlite3 native module is not built for this Node runtime");
    return true;
  }
  return false;
}

test("distinct SQLite tables queue as separate imports", () => {
  const first = makeImportQueueKey("/evidence/store.sqlite", { tableName: "events" });
  const second = makeImportQueueKey("/evidence/store.sqlite", { tableName: "users" });
  assert.notEqual(first, second);
});

test("generic SQLite import lists tables and streams one table", async (t) => {
  let Database;
  try {
    Database = require("better-sqlite3");
  } catch (err) {
    if (skipSqlite(t, err)) return;
    throw err;
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-sqlite-import-"));
  const dbPath = path.join(dir, "sample.sqlite");
  const sqlite = new Database(dbPath);
  sqlite.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, created_at TEXT);
    CREATE TABLE events (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT);
    INSERT INTO users (name, created_at) VALUES ('alice', '2026-08-01 12:00:00'), ('bob', '2026-08-02 08:15:00');
    INSERT INTO events (user_id, action) VALUES (1, 'login'), (1, 'export'), (2, 'login');
  `);
  sqlite.close();

  try {
    assert.equal(isSqliteFile(dbPath), true);
    const tables = listSqliteTables(dbPath);
    assert.deepEqual(
      tables.map((row) => ({ name: row.name, rowCount: row.rowCount })),
      [
        { name: "events", rowCount: 3 },
        { name: "users", rowCount: 2 },
      ],
    );

    const created = [];
    const batches = [];
    const fakeDb = {
      createTab(tabId, headers) { created.push({ tabId, headers }); },
      insertBatchArrays(_tabId, rows) { batches.push(rows); },
      finalizeImport() { return { rowCount: 2, tsColumns: ["created_at"], numericColumns: ["id"] }; },
    };
    const result = await parseSqliteTable(dbPath, "tab-1", fakeDb, null, "users");
    assert.deepEqual(created[0].headers, ["id", "name", "created_at"]);
    assert.equal(result.rowCount, 2);
    assert.equal(result.sourceFormat, "sqlite");
    assert.equal(batches.flat().length, 2);
    assert.equal(batches.flat()[0][1], "alice");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
