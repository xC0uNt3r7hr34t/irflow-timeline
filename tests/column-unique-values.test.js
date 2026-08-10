// Large-tab checkbox-filter values use a bounded row sample instead of a full-table GROUP BY.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();

const queryStore = require("../electron/db/query-store");
const TimelineDB = require("../electron/db");

test("getColumnUniqueValues samples unindexed columns on large tabs",
  { skip: HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "large-sample-tab";
    const headers = ["TimeCreated", "Channel"];
    db.createTab(tabId, headers);
    const meta = db.databases.get(tabId);
    meta.isLargeFile = true;
    meta.rowCount = 1_000_000;
    meta.indexedCols = new Set(["c0"]); // only timestamp indexed

    const ins = meta.db.prepare("INSERT INTO data (c0, c1) VALUES (?, ?)");
    for (let i = 0; i < 2000; i++) {
      ins.run(`2024-01-01 00:00:${String(i % 60).padStart(2, "0")}`, i % 3 === 0 ? "Security" : "Sysmon");
    }
    // Preserve the large-file population metadata while keeping the fixture small.
    meta.rowCount = 1_000_000;

    const full = db.getColumnUniqueValues(tabId, "Channel", { limit: 100 });
    assert.ok(full.sampled, "unindexed column on large tab should be sampled");
    assert.ok(full.values.some((r) => r.val === "Security"));
    assert.ok(full.values.some((r) => r.val === "Sysmon"));

    const indexed = db.getColumnUniqueValues(tabId, "TimeCreated", { limit: 100 });
    assert.equal(indexed.sampled, undefined, "indexed timestamp column uses full GROUP BY");
    assert.ok(Array.isArray(indexed.values));
  });

test("query-store exports sample tuning constants", () => {
  assert.equal(queryStore.LARGE_FILE_UNIQUE_SAMPLE_ROWS, 500_000);
  assert.equal(queryStore.LARGE_FILE_UNIQUE_SAMPLE_MIN_ROWS, 250_000);
});

test("getColumnUniqueValues accepts checkboxFilters as Set (AI history default Role filter)",
  { skip: HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime" },
  (t) => {
    const db = new TimelineDB();
    t.after(() => db.closeAll());
    const tabId = "checkbox-set-tab";
    const headers = ["Role", "Tool"];
    db.createTab(tabId, headers);
    const meta = db.databases.get(tabId);
    const ins = meta.db.prepare("INSERT INTO data (c0, c1) VALUES (?, ?)");
    ins.run("user", "OpenAI Codex");
    ins.run("assistant", "OpenAI Codex");
    ins.run("user", "Claude Code");
    meta.rowCount = 3;

    const result = db.getColumnUniqueValues(tabId, "Tool", {
      checkboxFilters: { Role: new Set(["user"]) },
      limit: 100,
    });
    const vals = result.values;
    assert.ok(Array.isArray(vals));
    assert.equal(vals.length, 2);
    const tools = vals.map((r) => r.val).sort();
    assert.deepEqual(tools, ["Claude Code", "OpenAI Codex"]);
  });
