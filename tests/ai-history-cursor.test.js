"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  extractCursorDir,
  extractCursorPath,
  isCursorHome,
  workspaceFromTranscriptPath,
} = require("../electron/parsers/ai-history/cursor");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");

const FIXTURE_CURSOR = path.join(__dirname, "fixtures/ai-history/cursor/.cursor");
const FIXTURE_TRANSCRIPT = path.join(
  FIXTURE_CURSOR,
  "projects/demo-project/agent-transcripts/a1111111-1111-4111-8111-111111111111/a1111111-1111-4111-8111-111111111111.jsonl",
);

test("workspaceFromTranscriptPath decodes project slug", () => {
  const ws = workspaceFromTranscriptPath(FIXTURE_TRANSCRIPT);
  assert.ok(ws.includes("demo-project"), `expected demo-project in workspace label, got ${ws}`);
});

test("extractCursorDir reads agent transcript messages", async () => {
  const rows = await extractCursorDir(FIXTURE_CURSOR, { user: "analyst" });
  assert.ok(rows.length >= 2);
  assert.equal(rows[0].Tool, "Cursor");
  assert.equal(rows[0].Role, "user");
  assert.match(rows[0].Summary, /Explain this function/);
  assert.equal(rows[1].Role, "assistant");
  assert.match(rows[1].InvokedTool, /Read/);
  assert.match(rows[1].InvokedTool, /Shell/);
  assert.equal(rows[1].ToolCommand, "node --test tests/sort.test.js");
  assert.equal(rows[1].ToolDescription, "Run the sort tests");
  const calls = JSON.parse(rows[1].ToolInput);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].input.working_directory, "/tmp/demo-project");
  assert.equal(rows[0].SessionId, "a1111111-1111-4111-8111-111111111111");
  assert.equal(rows[0].User, "analyst");
});

test("extractCursorPath accepts a single transcript file", async () => {
  const rows = await extractCursorPath(FIXTURE_TRANSCRIPT);
  assert.ok(rows.length >= 1);
  assert.ok(rows[0].LineNumber);
});

test("isCursorHome and import routing recognize .cursor", () => {
  assert.ok(isCursorHome(FIXTURE_CURSOR));
  assert.equal(detectAiHistoryImport(FIXTURE_CURSOR)?.tool, "cursor");
  const planned = planImportPaths([FIXTURE_CURSOR]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "cursor");
  assert.equal(path.resolve(planned[0].path), path.resolve(FIXTURE_CURSOR));
});
