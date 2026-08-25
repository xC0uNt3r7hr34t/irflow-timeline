"use strict";

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const registerAiHistoryHandlers = require("../electron/ipc/ai-history-handlers");
const {
  authorizeAiScanTarget,
  authorizeAiArtifactPick,
} = require("../electron/parsers/ai-history/path-auth");

const FIXTURE_CLAUDE = path.join(__dirname, "fixtures/ai-history/claude/.claude");
const FIXTURE_CHATGPT = path.join(__dirname, "fixtures/ai-history/chatgpt/com.openai.chat");
const FIXTURE_GEMINI = path.join(__dirname, "fixtures/ai-history/gemini/.gemini");
const FIXTURE_GROK = path.join(__dirname, "fixtures/ai-history/grok/.grok");
const FIXTURE_COPILOT_WS = path.join(
  __dirname,
  "fixtures/ai-history/copilot/Code/User/workspaceStorage",
);

function makeHandlers() {
  const handlers = {};
  const safeHandle = (ch, fn) => { handlers[ch] = fn; };
  registerAiHistoryHandlers(safeHandle, () => {}, { _tabMeta: new Map() });
  return handlers;
}

function grantCollection(dir) {
  authorizeAiScanTarget(dir);
}

function grantArtifact(targetPath) {
  authorizeAiArtifactPick(targetPath);
}

test("discover-ai-history-profile returns roots metadata", async () => {
  const h = makeHandlers();
  const r = await h["discover-ai-history-profile"](null, {});
  assert.ok(Array.isArray(r.roots));
  assert.ok(Number.isFinite(r.candidateCount));
  assert.equal(typeof r.hasScopeChoice, "boolean");
});

test("extract-ai-history-profile discoverOnly matches discover handler", async () => {
  const h = makeHandlers();
  const a = await h["discover-ai-history-profile"](null, { scanMode: "local" });
  const b = await h["extract-ai-history-profile"](null, { discoverOnly: true, scanMode: "local" });
  assert.equal(a.candidateCount, b.candidateCount);
  assert.equal(a.roots.length, b.roots.length);
});

test("discover-ai-history-profile finds Claude in KAPE-style folder", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ipc-folder-"));
  const claudeDir = path.join(root, "Users", "alice", ".claude");
  fs.mkdirSync(path.join(claudeDir, "projects", "p"), { recursive: true });
  fs.writeFileSync(path.join(claudeDir, "history.jsonl"), '{"display":"x","timestamp":1,"sessionId":"s"}\n');
  fs.writeFileSync(path.join(claudeDir, "projects", "p", "a.jsonl"), "");
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  grantCollection(root);
  const h = makeHandlers();
  const r = await h["discover-ai-history-profile"](null, { scanMode: "folder", scanRoot: root });
  assert.ok(r.roots.some((x) => x.tool === "claude-code"));
  assert.equal(r.scanMode, "folder");
});

test("decode-ai-history prepareOnly returns path without extracting", async () => {
  grantArtifact(FIXTURE_CLAUDE);
  const h = makeHandlers();
  const r = await h["decode-ai-history"](null, {
    path: FIXTURE_CLAUDE,
    tool: "claude-code",
    prepareOnly: true,
  });
  assert.equal(r.prepared, true);
  assert.equal(r.tool, "claude-code");
  assert.ok(r.extractTarget);
  assert.ok(!r.rows);
  assert.ok(!r.openedTab);
});

test("decode-ai-history extracts rows from a .claude directory", async () => {
  grantArtifact(FIXTURE_CLAUDE);
  const h = makeHandlers();
  const r = await h["decode-ai-history"](null, { path: FIXTURE_CLAUDE, tool: "claude-code" });
  assert.ok(!r.error, r.error);
  assert.ok(r.rows.length >= 3);
  assert.match(r.name, /Claude Code AI History/);
  assert.ok(r.rows[0].Timestamp && r.rows[0].Description);
});

test("decode-ai-history extracts Gemini CLI rows from .gemini folder", async () => {
  grantArtifact(FIXTURE_GEMINI);
  const h = makeHandlers();
  const r = await h["decode-ai-history"](null, { path: FIXTURE_GEMINI, tool: "gemini-cli" });
  assert.ok(!r.error, r.error);
  assert.ok(r.rows.length >= 2);
  assert.match(r.name, /Gemini CLI AI History/);
  assert.equal(r.tool, "gemini-cli");
});

test("decode-ai-history extracts exact Grok Build terminal evidence", async () => {
  grantArtifact(FIXTURE_GROK);
  const h = makeHandlers();
  const r = await h["decode-ai-history"](null, { path: FIXTURE_GROK, tool: "grok-build" });
  assert.ok(!r.error, r.error);
  assert.ok(r.rows.length >= 7);
  assert.match(r.name, /Grok Build AI History/);
  assert.equal(r.tool, "grok-build");
  assert.ok(r.rows.some((row) =>
    row.InvokedTool === "run_terminal_command"
    && row.ToolCommand === "printf '%s\\n' \"quoted value\""));
});

test("decode-ai-history extracts ChatGPT rows from app data folder", async () => {
  grantArtifact(FIXTURE_CHATGPT);
  const h = makeHandlers();
  const r = await h["decode-ai-history"](null, { path: FIXTURE_CHATGPT, tool: "chatgpt" });
  assert.ok(!r.error, r.error);
  assert.ok(r.rows.length >= 1);
  assert.match(r.name, /ChatGPT AI History/);
  assert.equal(r.tool, "chatgpt");
});

test("decode-ai-history extracts Copilot rows from workspaceStorage fixture", async () => {
  grantArtifact(FIXTURE_COPILOT_WS);
  const h = makeHandlers();
  const r = await h["decode-ai-history"](null, { path: FIXTURE_COPILOT_WS, tool: "copilot" });
  assert.ok(!r.error, r.error);
  assert.ok(r.rows.length >= 1);
  assert.equal(r.tool, "copilot");
});

test("decode-ai-history windsurf resolves User dir without ReferenceError", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-windsurf-"));
  const userDir = path.join(root, "Windsurf", "User");
  fs.mkdirSync(path.join(userDir, "workspaceStorage"), { recursive: true });
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  grantArtifact(userDir);
  const h = makeHandlers();
  const r = await h["decode-ai-history"](null, { path: userDir, tool: "windsurf" });
  assert.ok(!String(r.error || "").includes("resolveWindsurfUserDir is not defined"), r.error);
});
