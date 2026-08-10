"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  isCopilotCliRoot,
  resolveCopilotCliRoot,
  isCopilotCliArtifactPath,
  listCopilotCliArtifactFiles,
  extractCopilotCliPath,
} = require("../electron/parsers/ai-history/copilot-cli");
const { extractCopilotPath } = require("../electron/parsers/ai-history/copilot");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");

function buildCopilotCliFixture(t) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-copilot-cli-"));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const root = path.join(temp, "Users", "alice", ".copilot");
  const session = path.join(root, "session-state", "session-123");
  fs.mkdirSync(path.join(session, "checkpoints"), { recursive: true });
  fs.mkdirSync(path.join(session, "files"), { recursive: true });
  fs.mkdirSync(path.join(root, "command-history-state"), { recursive: true });
  fs.mkdirSync(path.join(root, "logs"), { recursive: true });
  fs.mkdirSync(path.join(root, "mcp-secrets"), { recursive: true });

  fs.writeFileSync(path.join(session, "workspace.yaml"), [
    "id: session-123",
    "cwd: /evidence/demo-repo",
    "name: Demo investigation",
    "model: claude-sonnet-4.5",
  ].join("\n"));
  fs.writeFileSync(path.join(session, "events.jsonl"), [
    JSON.stringify({
      type: "session.start",
      data: {
        sessionId: "session-123",
        startTime: "2026-07-25T10:00:00.000Z",
        context: { cwd: "/evidence/demo-repo" },
      },
      id: "event-1",
      timestamp: "2026-07-25T10:00:00.000Z",
      parentId: null,
    }),
    JSON.stringify({
      type: "user.message",
      data: { content: "Check the repository state" },
      id: "event-2",
      timestamp: "2026-07-25T10:00:01.000Z",
      parentId: "event-1",
    }),
    JSON.stringify({
      type: "tool.execution_start",
      data: {
        toolCallId: "call-1",
        toolName: "bash",
        arguments: { command: "git status --short && printf '%s' \"$PWD\"", description: "Inspect state" },
      },
      id: "event-3",
      timestamp: "2026-07-25T10:00:02.000Z",
      parentId: "event-2",
    }),
    JSON.stringify({
      type: "tool.execution_complete",
      data: {
        toolCallId: "call-1",
        success: true,
        model: "claude-sonnet-4.5",
        result: { content: " M src/app.js" },
      },
      id: "event-4",
      timestamp: "2026-07-25T10:00:03.000Z",
      parentId: "event-3",
    }),
    JSON.stringify({
      type: "assistant.message",
      data: { content: "The repository contains one modified file." },
      id: "event-5",
      timestamp: "2026-07-25T10:00:04.000Z",
      parentId: "event-2",
    }),
  ].join("\n"));
  fs.writeFileSync(path.join(session, "plan.md"), "# Plan\n- Inspect state\n- Report findings\n");
  fs.writeFileSync(path.join(session, "checkpoints", "001.json"), JSON.stringify({
    summary: "Repository state inspected",
    inputTokens: 120,
  }));
  fs.writeFileSync(path.join(session, "files", "evidence-note.txt"), "TRACKED-FILE-CONTENT-MUST-NOT-BE-IMPORTED");
  fs.writeFileSync(path.join(root, "command-history-state", "history.json"), JSON.stringify({
    entries: [
      { command: "npm test -- --test-name-pattern copilot", timestamp: "2026-07-25T09:59:00.000Z" },
    ],
  }));
  fs.writeFileSync(path.join(root, "logs", "process-1.log"), "Authorization: Bearer SHOULD-NOT-BE-IMPORTED");
  fs.writeFileSync(path.join(root, "config.json"), JSON.stringify({ oauthToken: "SHOULD-NOT-BE-IMPORTED" }));
  fs.writeFileSync(path.join(root, "mcp-secrets", "token"), "SHOULD-NOT-BE-IMPORTED");
  return { root, session };
}

function buildCopilotSessionStoreFixture(dbPath) {
  let Database;
  try {
    Database = require("better-sqlite3");
    const probe = path.join(os.tmpdir(), `irflow-copilot-sqlite-probe-${process.pid}.db`);
    const db = new Database(probe);
    db.close();
    try { fs.unlinkSync(probe); } catch { /* ignore */ }
  } catch (error) {
    if (error.code === "ERR_DLOPEN_FAILED") return false;
    throw error;
  }

  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE sessions (
      session_id TEXT PRIMARY KEY,
      title TEXT,
      workspace TEXT,
      updated_at INTEGER,
      access_token TEXT
    );
  `);
  db.prepare(`
    INSERT INTO sessions (session_id, title, workspace, updated_at, access_token)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    "session-store-1",
    "Investigate persistence",
    "/evidence/case",
    1704067200000,
    "SECRET-MUST-NOT-BE-IMPORTED",
  );
  db.close();
  return true;
}

test("Copilot CLI root and artifact discovery excludes credential-bearing stores", (t) => {
  const { root, session } = buildCopilotCliFixture(t);
  assert.equal(isCopilotCliRoot(root), true);
  assert.equal(resolveCopilotCliRoot(path.join(session, "events.jsonl")), root);
  assert.equal(isCopilotCliArtifactPath(path.join(session, "events.jsonl")), true);
  assert.equal(isCopilotCliArtifactPath(path.join(root, "config.json")), false);
  assert.equal(isCopilotCliArtifactPath(path.join(root, "mcp-secrets", "token")), false);

  const files = listCopilotCliArtifactFiles(root);
  assert.ok(files.some((file) => file.endsWith("events.jsonl")));
  assert.ok(files.every((file) => !file.includes(`${path.sep}mcp-secrets${path.sep}`)));
  assert.ok(files.every((file) => path.basename(file) !== "config.json"));
});

test("Copilot CLI parsing preserves exact tool commands and inventories sensitive auxiliaries safely", async (t) => {
  const { root } = buildCopilotCliFixture(t);
  const rows = await extractCopilotCliPath(root, { user: "alice", host: "host1" });

  const toolCall = rows.find((row) => row.RecordType === "tool.execution_start");
  assert.ok(toolCall);
  assert.equal(toolCall.ToolCommand, "git status --short && printf '%s' \"$PWD\"");
  assert.equal(toolCall.InvokedTool, "bash");

  const result = rows.find((row) => row.RecordType === "tool.execution_complete");
  assert.match(result?.FullText || "", /src\/app\.js/);
  assert.equal(result?.SessionId, "session-123");

  const commandHistory = rows.find((row) => row.RecordType === "command_history");
  assert.equal(commandHistory?.ToolCommand, "npm test -- --test-name-pattern copilot");
  assert.ok(rows.some((row) => row.RecordType === "plan"));
  assert.ok(rows.some((row) => row.RecordType === "checkpoint"));
  assert.ok(rows.some((row) => row.RecordType === "tracked_file_inventory"));
  assert.ok(rows.some((row) => row.RecordType === "log_inventory"));

  const allText = rows.map((row) => `${row.Summary}\n${row.FullText}\n${row.ToolInput}`).join("\n");
  assert.doesNotMatch(allText, /TRACKED-FILE-CONTENT-MUST-NOT-BE-IMPORTED/);
  assert.doesNotMatch(allText, /Authorization: Bearer SHOULD-NOT-BE-IMPORTED/);
  assert.doesNotMatch(allText, /oauthToken|SHOULD-NOT-BE-IMPORTED/);
  assert.equal(rows._copilotStats.cli, true);
});

test("unified Copilot extractor streams CLI rows and import routing consolidates .copilot", async (t) => {
  const { root, session } = buildCopilotCliFixture(t);
  const streamed = [];
  const returned = await extractCopilotPath(root, {}, {
    onExtractedRows: (chunk) => streamed.push(...chunk),
  });
  assert.equal(returned.length, 0);
  assert.equal(returned._copilotStats.cli, true);
  assert.ok(streamed.some((row) => row.RecordType === "user.message"));

  assert.equal(detectAiHistoryImport(root)?.tool, "copilot");
  assert.equal(detectAiHistoryImport(path.join(session, "events.jsonl"))?.target, root);
  const planned = planImportPaths([
    path.join(session, "events.jsonl"),
    path.join(session, "plan.md"),
  ]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].path, root);
  assert.equal(planned[0].opts.aiHistoryTool, "copilot");
});

test("Copilot CLI session-store snapshot extracts safe metadata and excludes secret columns", async (t) => {
  const { root } = buildCopilotCliFixture(t);
  const dbPath = path.join(root, "session-store.db");
  if (!buildCopilotSessionStoreFixture(dbPath)) {
    t.skip("better-sqlite3 not available in this Node runtime");
    return;
  }

  const rows = await extractCopilotCliPath(root);
  assert.ok(rows.some((row) => row.RecordType === "session_store_table"));
  const sessionRow = rows.find((row) => row.RecordType === "session_store_sessions");
  assert.equal(sessionRow?.SessionId, "session-store-1");
  assert.match(sessionRow?.FullText || "", /Investigate persistence/);
  assert.doesNotMatch(
    rows.map((row) => `${row.Summary}\n${row.FullText}`).join("\n"),
    /SECRET-MUST-NOT-BE-IMPORTED/,
  );
});
