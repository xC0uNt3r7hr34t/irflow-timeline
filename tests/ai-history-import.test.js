"use strict";

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  planImportPaths,
  detectAiHistoryImport,
  isClaudeJsonlPath,
} = require("../electron/parsers/ai-history-import");
const { historyLineText, parseHistoryLine } = require("../electron/parsers/ai-history/claude-code");

const FIXTURE_CLAUDE = path.join(__dirname, "fixtures/ai-history/claude/.claude");
const FIXTURE_CHATGPT = path.join(__dirname, "fixtures/ai-history/chatgpt/com.openai.chat");
const FIXTURE_GEMINI = path.join(__dirname, "fixtures/ai-history/gemini/.gemini");
const FIXTURE_GEMINI_SESSION = path.join(
  FIXTURE_GEMINI,
  "tmp/a1b2c3d4/chats/session-demo.json",
);

test("historyLineText reads display and pastedContents payloads", () => {
  assert.equal(historyLineText({ display: "hello" }), "hello");
  assert.equal(
    historyLineText({ pastedContents: { "0": { text: "from clipboard" } }, timestamp: 1 }),
    "from clipboard",
  );
  assert.equal(historyLineText({ pastedContents: {}, timestamp: 1 }), "");
});

test("parseHistoryLine ignores empty pastedContents-only rows", () => {
  assert.equal(parseHistoryLine({ pastedContents: {}, timestamp: 1, sessionId: "s" }, "f"), null);
  const row = parseHistoryLine({
    display: "fix this bug",
    timestamp: 1704067200000,
    sessionId: "s1",
    project: "/tmp",
  }, "history.jsonl");
  assert.ok(row);
  assert.equal(row.Summary, "fix this bug");
  assert.equal(row.Timestamp, "2024-01-01 00:00:00");
});

test("detectAiHistoryImport recognizes .claude dir and history.jsonl", () => {
  assert.equal(detectAiHistoryImport(FIXTURE_CLAUDE)?.tool, "claude-code");
  const hist = path.join(FIXTURE_CLAUDE, "history.jsonl");
  assert.ok(isClaudeJsonlPath(hist));
  assert.equal(detectAiHistoryImport(hist)?.tool, "claude-code");
});

test("planImportPaths merges multiple Claude JSONL into one .claude import", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-plan-claude-"));
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  const claudeDir = path.join(root, "Users", "u", ".claude");
  const chats = path.join(claudeDir, "projects", "p", "chats");
  fs.mkdirSync(chats, { recursive: true });
  fs.writeFileSync(path.join(claudeDir, "history.jsonl"), '{"display":"a","timestamp":1,"sessionId":"s"}\n');
  fs.writeFileSync(path.join(claudeDir, "projects", "p", "a.jsonl"), "{}");

  const sessionA = path.join(chats, "session-a.jsonl");
  const sessionB = path.join(chats, "session-b.jsonl");
  fs.copyFileSync(
    path.join(FIXTURE_CLAUDE, "projects/demo-app/sess-abc.jsonl"),
    sessionA,
  );
  fs.copyFileSync(sessionA, sessionB);

  const planned = planImportPaths([
    path.join(claudeDir, "history.jsonl"),
    sessionA,
    sessionB,
  ]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "claude-code");
  assert.ok(planned[0].path.endsWith(".claude"));
});

test("planImportPaths keeps a single Claude JSONL as one file import", () => {
  const planned = planImportPaths([path.join(FIXTURE_CLAUDE, "history.jsonl")]);
  assert.equal(planned.length, 1);
  assert.ok(!planned[0].opts?.aiHistoryTool);
});

test("detectAiHistoryImport recognizes ChatGPT and Gemini roots", () => {
  assert.equal(detectAiHistoryImport(FIXTURE_CHATGPT)?.tool, "chatgpt");
  assert.equal(detectAiHistoryImport(FIXTURE_GEMINI)?.tool, "gemini-cli");
  assert.equal(detectAiHistoryImport(FIXTURE_GEMINI_SESSION)?.tool, "gemini-cli");
});

test("planImportPaths merges multiple ChatGPT stores into one app-data import", () => {
  const ldb = path.join(FIXTURE_CHATGPT, "Local Storage/leveldb/000003.ldb");
  const planned = planImportPaths([ldb, ldb]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "chatgpt");
  assert.ok(planned[0].path.includes("com.openai.chat"));
});

test("planImportPaths merges multiple Gemini sessions into one .gemini import", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-plan-gemini-"));
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  const geminiDir = path.join(root, "Users", "u", ".gemini");
  const chats = path.join(geminiDir, "tmp", "abc", "chats");
  fs.mkdirSync(chats, { recursive: true });
  const sessionA = path.join(chats, "session-a.json");
  const sessionB = path.join(chats, "session-b.json");
  fs.copyFileSync(FIXTURE_GEMINI_SESSION, sessionA);
  fs.copyFileSync(FIXTURE_GEMINI_SESSION, sessionB);

  const planned = planImportPaths([sessionA, sessionB]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "gemini-cli");
  assert.ok(planned[0].path.endsWith(".gemini"));
});

test("planImportPaths opens ChatGPT app folder as one consolidated import", () => {
  const planned = planImportPaths([FIXTURE_CHATGPT]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "chatgpt");
});
