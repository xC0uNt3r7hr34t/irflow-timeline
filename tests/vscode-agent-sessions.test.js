"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const {
  rowsFromAgentSessionsCache,
  rowsFromChatSessionStoreIndex,
  matchesProviderFilter,
  COPILOT_PROVIDER_RE,
  CODEX_PROVIDER_RE,
  extractChatFromVscdb,
  supplementCodexFromVsCodeAgentSessions,
} = require("../electron/parsers/ai-history/vscode-chat-db");
const { buildCopilotEmptyExtractError, buildCopilotExtractionStats } = require("../electron/parsers/ai-history/import-meta");

test("rowsFromAgentSessionsCache extracts Codex agent labels", () => {
  const data = [{
    providerType: "openai-codex",
    providerLabel: "Codex",
    resource: "openai-codex://route/local/019e7364-8c0d-7d43-b727-b0a966de6a13",
    label: "Review my codebase",
    timing: { created: 1780052429000 },
  }];
  const { rows, alternateAgentSessions } = rowsFromAgentSessionsCache(
    data,
    "/tmp/state.vscdb",
    "OpenAI Codex",
    { user: "alice" },
    "ws-hash",
    { providerFilter: CODEX_PROVIDER_RE },
  );
  assert.equal(rows.length, 1);
  assert.equal(rows[0].Role, "user");
  assert.match(rows[0].Summary, /Review my codebase/);
  assert.equal(rows[0].Model, "Codex");
  assert.equal(alternateAgentSessions, 0);
});

test("rowsFromAgentSessionsCache counts alternate providers under Copilot filter", () => {
  const data = [{
    providerType: "openai-codex",
    providerLabel: "Codex",
    resource: "openai-codex://route/local/abc",
    label: "Codex prompt",
    timing: { created: 1780052429000 },
  }];
  const { rows, alternateAgentSessions } = rowsFromAgentSessionsCache(
    data,
    "/tmp/state.vscdb",
    "GitHub Copilot",
    {},
    "ws-hash",
    { providerFilter: COPILOT_PROVIDER_RE },
  );
  assert.equal(rows.length, 0);
  assert.equal(alternateAgentSessions, 1);
});

test("rowsFromChatSessionStoreIndex skips empty New Chat shells", () => {
  const rows = rowsFromChatSessionStoreIndex(
    {
      version: 1,
      entries: {
        a: { sessionId: "a", title: "New Chat", isEmpty: true, lastMessageDate: 1 },
        b: { sessionId: "b", title: "Investigate lateral movement", isEmpty: false, lastMessageDate: 2 },
      },
    },
    "/tmp/state.vscdb",
    "GitHub Copilot",
    {},
    "ws-hash",
  );
  assert.equal(rows.length, 1);
  assert.match(rows[0].Summary, /Investigate lateral movement/);
});

test("buildCopilotEmptyExtractError mentions Codex agent sessions when present", () => {
  const stats = buildCopilotExtractionStats([], {
    sessionsScanned: 13,
    emptySessions: 13,
    alternateAgentSessions: 50,
  });
  const msg = buildCopilotEmptyExtractError(stats);
  assert.match(msg, /13 session file/);
  assert.match(msg, /50 VS Code Codex/);
});

test("Codex VS Code supplement never probes global live-host roots implicitly", async () => {
  const result = await supplementCodexFromVsCodeAgentSessions({}, {});
  assert.equal(result.rows.length, 0);
  assert.equal(result.stats.databases, 0);
});

test("extractChatFromVscdb reads agentSessions.model.cache", (t) => {
  let Database;
  try {
    Database = require("better-sqlite3");
    const probe = path.join(os.tmpdir(), `irflow-sqlite-probe-${process.pid}.db`);
    const d = new Database(probe);
    d.close();
    fs.unlinkSync(probe);
  } catch (e) {
    if (e.code === "ERR_DLOPEN_FAILED") {
      t.skip("better-sqlite3 not available for plain Node");
      return;
    }
    throw e;
  }

  const dbPath = path.join(os.tmpdir(), `vscode-agent-${process.pid}.vscdb`);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  t.after(() => { try { fs.unlinkSync(dbPath); } catch { /* ignore */ } });

  const db = new Database(dbPath);
  db.exec("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)");
  db.prepare("INSERT INTO ItemTable (key, value) VALUES (?, ?)").run(
    "agentSessions.model.cache",
    JSON.stringify([{
      providerType: "github-copilot",
      providerLabel: "Copilot",
      resource: "copilot://session/11111111-1111-4111-8111-111111111111",
      label: "Explain this function",
      timing: { created: 1704067200000 },
    }]),
  );
  db.close();

  const { rows } = extractChatFromVscdb(
    dbPath,
    "GitHub Copilot",
    { user: "u" },
    "ws1",
    { providerFilter: COPILOT_PROVIDER_RE },
  );
  assert.equal(rows.length, 1);
  assert.match(rows[0].Summary, /Explain this function/);
});
