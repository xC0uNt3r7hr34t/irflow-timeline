"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  extractCopilotPath,
  sessionRowsFromSnapshot,
  extractMessageText,
  extractResponseText,
  decodeWorkspaceUri,
  buildSnapshotFromJsonlLines,
} = require("../electron/parsers/ai-history/copilot");
const { formatCopilotImportNotice, buildCopilotExtractionStats } = require("../electron/parsers/ai-history/import-meta");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");

const FIXTURE_WS = path.join(
  __dirname,
  "fixtures/ai-history/copilot/Code/User/workspaceStorage/wshash123",
);
const FIXTURE_SESSION = path.join(FIXTURE_WS, "chatSessions/copilot-session-1.json");
const FIXTURE_STORAGE = path.join(__dirname, "fixtures/ai-history/copilot/Code/User/workspaceStorage");

test("decodeWorkspaceUri resolves file URIs", () => {
  const p = decodeWorkspaceUri("file:///tmp/copilot-demo-repo");
  assert.ok(p.endsWith("/copilot-demo-repo") || p.includes("copilot-demo-repo"));
});

test("extractMessageText and extractResponseText", () => {
  assert.equal(extractMessageText({ text: " hello " }), "hello");
  assert.match(
    extractResponseText([{ kind: "markdownContent", content: { value: "Run **npm test**" } }]),
    /npm test/,
  );
});

test("sessionRowsFromSnapshot builds user and assistant rows", () => {
  const snapshot = {
    sessionId: "s1",
    creationDate: 1704067200000,
    requests: [{
      requestId: "r1",
      timestamp: 1704067200000,
      modelId: "copilot/gpt-4o",
      message: { text: "Question?" },
      response: [{ kind: "markdownContent", content: { value: "Answer." } }],
    }],
  };
  const rows = sessionRowsFromSnapshot(snapshot, "/chat.json", "/tmp/repo", { user: "u" });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].Role, "user");
  assert.equal(rows[1].Role, "assistant");
  assert.equal(rows[0].Workspace, "repo");
  assert.equal(rows[0].Model, "copilot/gpt-4o");
});

test("buildSnapshotFromJsonlLines replays kind 1 incremental request object", () => {
  const snap = buildSnapshotFromJsonlLines([
    '{"kind":0,"v":{"sessionId":"s","requests":[]}}',
    '{"kind":1,"v":{"requestId":"x","message":{"text":"Hi"},"response":[{"kind":"markdownContent","content":{"value":"Hello"}}]}}',
  ]);
  assert.equal(snap.requests.length, 1);
  assert.match(extractMessageText(snap.requests[0].message), /Hi/);
});

test("buildSnapshotFromJsonlLines replays kind 0/2/1 operations", () => {
  const lines = [
    '{"kind":0,"v":{"sessionId":"s","requests":[]}}',
    '{"kind":2,"v":{"requestId":"a","message":{"text":"Q"},"response":[]}}',
    '{"kind":1,"v":{"requests":[{"requestId":"a","message":{"text":"Q"},"response":[{"kind":"markdownContent","content":{"value":"A"}}]}]}}',
  ];
  const snap = buildSnapshotFromJsonlLines(lines);
  assert.equal(snap.requests.length, 1);
  assert.match(extractResponseText(snap.requests[0].response), /A/);
});

test("extractCopilotPath reads workspace chatSessions", async () => {
  const rows = await extractCopilotPath(FIXTURE_WS);
  assert.ok(rows.length >= 2);
  assert.equal(rows[0].Tool, "GitHub Copilot");
  assert.match(rows[0].Summary, /run tests/i);
  assert.match(rows[1].Summary, /npm test/i);
  const stats = buildCopilotExtractionStats(rows, rows._copilotStats || {});
  assert.ok(stats.sessionsWithMessages >= 1);
  assert.match(formatCopilotImportNotice(stats), /GitHub Copilot/);
});

test("extractCopilotPath prefers JSONL over JSON for same session id", async () => {
  const rows = await extractCopilotPath(FIXTURE_WS);
  assert.ok(rows.some((r) => /JSONL question/i.test(r.Summary)));
});

test("streamed extraction (onExtractedRows) yields the SAME rows as in-memory — and returns none", async () => {
  // Guards the memory refactor: the streamed worker path must surface exactly the same messages as the
  // in-memory path, just emitted per-file to the sink instead of held as one big array.
  const { aiHistoryDedupeKey } = require("../electron/parsers/ai-history/row-utils");
  const inMem = await extractCopilotPath(FIXTURE_STORAGE);
  const streamed = [];
  const ret = await extractCopilotPath(FIXTURE_STORAGE, {}, { onExtractedRows: (chunk) => streamed.push(...chunk) });

  assert.equal(ret.length, 0, "streamed path returns no rows (they went to the sink via onExtractedRows)");
  assert.ok(ret._copilotStats, "streamed return still carries _copilotStats");
  assert.ok(streamed.length >= 2, "streamed at least the session rows");

  const keySet = (arr) => [...new Set(arr.map(aiHistoryDedupeKey))].sort();
  assert.deepEqual(keySet(streamed), keySet(inMem), "streamed rows == in-memory rows (same unique messages)");
});

test("detectAiHistoryImport and planImportPaths recognize Copilot paths", () => {
  assert.equal(detectAiHistoryImport(FIXTURE_SESSION)?.tool, "copilot");
  assert.equal(detectAiHistoryImport(FIXTURE_STORAGE)?.tool, "copilot");
  const planned = planImportPaths([FIXTURE_STORAGE]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "copilot");
});
