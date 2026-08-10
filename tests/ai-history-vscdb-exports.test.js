"use strict";

// Contract guard: codex-state-sqlite.js destructures listTables from vscdb-kv. It was used but
// not exported, so `listTables(db)` threw "is not a function" inside a try/catch and Codex
// state.sqlite extraction silently returned zero rows on every run. This needs no SQLite binding.

const { test } = require("node:test");
const assert = require("node:assert/strict");

const vscdbKv = require("../electron/parsers/ai-history/vscdb-kv");

test("vscdb-kv exports the helpers codex-state-sqlite imports", () => {
  // The exact destructure in codex-state-sqlite.js:9
  const { openVscdbReadOnly, listTables, safeCloseDb } = vscdbKv;
  assert.equal(typeof openVscdbReadOnly, "function");
  assert.equal(typeof listTables, "function", "listTables must be exported (codex state.sqlite depends on it)");
  assert.equal(typeof safeCloseDb, "function");
});
