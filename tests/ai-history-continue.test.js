"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  isContinueRoot,
  extractContinueDir,
  extractContinuePath,
} = require("../electron/parsers/ai-history/continue");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");

const FIXTURE = path.join(__dirname, "fixtures/ai-history/continue/.continue");
const FIXTURE_SESSION = path.join(FIXTURE, "sessions/sess-fixture-1.json");

test("isContinueRoot recognizes sessions folder", () => {
  assert.ok(isContinueRoot(FIXTURE));
});

test("extractContinueDir reads session JSON messages", async () => {
  const rows = await extractContinueDir(FIXTURE, { user: "analyst" });
  assert.ok(rows.length >= 2);
  assert.equal(rows[0].Tool, "Continue");
  assert.match(rows[0].Summary, /list processes/i);
  assert.equal(rows[1].Role, "assistant");
  assert.ok(rows[0].FullText);
  assert.ok(rows[0].FullText.length >= rows[0].Summary.length);
});

test("detectAiHistoryImport and planImportPaths recognize Continue paths", () => {
  assert.equal(detectAiHistoryImport(FIXTURE)?.tool, "continue");
  assert.equal(detectAiHistoryImport(FIXTURE_SESSION)?.tool, "continue");
  const planned = planImportPaths([FIXTURE, FIXTURE_SESSION]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "continue");
});
