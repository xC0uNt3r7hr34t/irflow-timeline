"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("fs");
const os = require("os");

const {
  extractCursorComposerStores,
  isCursorUserDataDir,
} = require("../electron/parsers/ai-history/cursor-composer");
const {
  buildCursorComposerFixture,
  buildCursorConversationSearchFixture,
} = require("./helpers/vscdb-builder");

const FIXTURE_CURSOR = path.join(__dirname, "fixtures/ai-history/cursor/.cursor");

test("extractCursorComposerStores reads bubble messages from state.vscdb", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-vscdb-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const userDir = path.join(tmp, "Library", "Application Support", "Cursor", "User");
  const globalDb = path.join(userDir, "globalStorage", "state.vscdb");
  if (!buildCursorComposerFixture(globalDb)) {
    t.skip("better-sqlite3 not available in this Node runtime");
    return;
  }

  const agentHome = path.join(tmp, ".cursor");
  fs.mkdirSync(path.join(agentHome, "projects"), { recursive: true });

  const { rows, stats } = await extractCursorComposerStores(agentHome, { user: "analyst" }, {
    userDataDirs: [userDir],
  });
  assert.ok(stats.databases >= 1);
  assert.ok(rows.length >= 2);
  assert.equal(rows[0].Tool, "Cursor");
  assert.match(rows.find((r) => r.Role === "user")?.Summary || "", /composer DB/);
});

test("extractCursorDir merges transcript and composer rows when vscdb present", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-merge-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const globalDb = path.join(tmp, "globalStorage", "state.vscdb");
  if (!buildCursorComposerFixture(globalDb)) {
    t.skip("better-sqlite3 not available in this Node runtime");
    return;
  }

  const { extractCursorDir } = require("../electron/parsers/ai-history/cursor");
  const rows = await extractCursorDir(FIXTURE_CURSOR, { user: "u" });
  assert.ok(rows.length >= 2);
});

test("Cursor User root parses conversation-search.db FTS bodies with source metadata", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-search-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const userDir = path.join(tmp, "Library", "Application Support", "Cursor", "User");
  const searchDb = path.join(userDir, "globalStorage", "conversation-search.db");
  if (!buildCursorConversationSearchFixture(searchDb)) {
    t.skip("better-sqlite3 not available in this Node runtime");
    return;
  }

  const { extractCursorPath, resolveCursorRoot } = require("../electron/parsers/ai-history/cursor");
  const { detectAiHistoryImport } = require("../electron/parsers/ai-history-import");
  assert.equal(isCursorUserDataDir(userDir), true);
  assert.equal(resolveCursorRoot(searchDb), userDir);
  assert.equal(detectAiHistoryImport(searchDb)?.target, userDir);

  const rows = await extractCursorPath(userDir, { user: "analyst" });
  const indexed = rows.find((row) => row.RecordType === "conversation_search");
  assert.ok(indexed);
  assert.equal(indexed.SessionId, "cursor-search-session-1");
  assert.equal(indexed.Summary, "Investigate persistence");
  assert.match(indexed.FullText, /suspicious PowerShell execution/);
  assert.equal(indexed.Timestamp, "2024-01-01 00:00:00");
  const metadataOnly = rows.find((row) => row.SessionId === "cursor-search-session-2");
  assert.match(metadataOnly?.Summary || "", /archived/i);
  assert.match(metadataOnly?.FullText || "", /"bodyPresent": false/);
  assert.equal(rows._cursorComposerStats.searchRows, 2);
});
