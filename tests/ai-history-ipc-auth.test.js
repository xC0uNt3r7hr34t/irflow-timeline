"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const registerAiHistoryHandlers = require("../electron/ipc/ai-history-handlers");
const registerSessionHandlers = require("../electron/ipc/session-handlers");
const { planImportPaths } = require("../electron/parsers/ai-history-import");
const { authorizeAiArtifactPick } = require("../electron/parsers/ai-history/path-auth");

function captureHandlers(register, ctx = {}) {
  const handlers = {};
  register((channel, handler) => { handlers[channel] = handler; }, () => {}, ctx);
  return handlers;
}

function makeClaudeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ipc-auth-"));
  const claude = path.join(root, ".claude");
  fs.mkdirSync(path.join(claude, "projects", "demo"), { recursive: true });
  fs.writeFileSync(path.join(claude, "history.jsonl"), '{"display":"hello","timestamp":1,"sessionId":"s"}\n');
  fs.writeFileSync(path.join(claude, "projects", "demo", "s.jsonl"), "");
  return { root, claude };
}

test("extract-ai-history-profile rejects renderer-provided roots that were not already authorized", async () => {
  const { root, claude } = makeClaudeRoot();
  try {
    const handlers = captureHandlers(registerAiHistoryHandlers);
    const result = await handlers["extract-ai-history-profile"](null, {
      roots: [{ tool: "claude-code", path: claude, label: "Claude Code" }],
      includeSubagents: false,
      scanMode: "local",
    });

    assert.match(result.error, /not authorized/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("discover-ai-history-profile rejects renderer-supplied folder roots without a picker grant", async () => {
  const { root } = makeClaudeRoot();
  try {
    const handlers = captureHandlers(registerAiHistoryHandlers);
    const result = await handlers["discover-ai-history-profile"](null, {
      scanMode: "folder",
      scanRoot: root,
    });

    assert.match(result.error, /not authorized/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("import-files ignores forged renderer items when no main-process plan exists", async () => {
  const { root, claude } = makeClaudeRoot();
  try {
    const planned = registerSessionHandlers._applyClientAiScopeChoices(
      planImportPaths([]),
      [{
        path: claude,
        opts: { aiHistoryTool: "claude-code", aiHistoryIncludeSubagents: true },
      }],
    );

    assert.deepEqual(planned, []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("import-files carries only the scope choice onto a main-process-planned AI import", async () => {
  const { root, claude } = makeClaudeRoot();
  try {
    const planned = registerSessionHandlers._applyClientAiScopeChoices(
      planImportPaths([claude]),
      [{
        path: claude,
        opts: { aiHistoryTool: "claude-code", aiHistoryIncludeSubagents: true },
      }],
    );

    assert.equal(planned.length, 1);
    assert.equal(planned[0].path, path.resolve(claude));
    assert.equal(planned[0].needsScopeChoice, false);
    assert.deepEqual(planned[0].opts, {
      aiHistoryTool: "claude-code",
      aiHistoryIncludeSubagents: true,
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("open-ai-source refuses unauthorized renderer paths", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-open-source-deny-"));
  const secret = path.join(root, "secret.txt");
  fs.writeFileSync(secret, "secret");
  let called = false;
  try {
    const result = await registerSessionHandlers._openAuthorizedAiSource(
      { filePath: secret, lineNumber: 7 },
      async () => {
        called = true;
        return "";
      },
    );

    assert.equal(result.__ipcError, true);
    assert.match(result.message, /not authorized/i);
    assert.equal(called, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("open-ai-source opens a previously authorized AI artifact path", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-open-source-allow-"));
  const source = path.join(root, ".claude", "history.jsonl");
  fs.mkdirSync(path.dirname(source), { recursive: true });
  fs.writeFileSync(source, "{}\n");
  authorizeAiArtifactPick(path.dirname(source));
  const opened = [];
  try {
    const result = await registerSessionHandlers._openAuthorizedAiSource(
      { filePath: source, lineNumber: 12 },
      async (openedPath) => {
        opened.push(openedPath);
        return "";
      },
    );

    assert.deepEqual(result, { ok: true, lineNumber: "12" });
    assert.equal(opened.length, 1);
    assert.equal(opened[0], fs.realpathSync.native(source));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
