"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  extractGeminiSessionFile,
  extractGeminiSessionJsonlFile,
  extractGeminiShellHistoryFile,
  extractGeminiLogsFile,
  extractGeminiCliDir,
  extractGeminiCliPath,
  isGeminiCliRoot,
  isGeminiSessionFile,
  isGeminiShellHistoryFile,
  isGeminiLogsFile,
  countGeminiSessions,
} = require("../electron/parsers/ai-history/gemini-cli");

const FIXTURE_GEMINI = path.join(__dirname, "fixtures/ai-history/gemini/.gemini");
const FIXTURE_GEMINI_LOGS = path.join(__dirname, "fixtures/ai-history/gemini-logs/.gemini");
const FIXTURE_SESSION = path.join(FIXTURE_GEMINI, "tmp/a1b2c3d4/chats/session-demo.json");
const FIXTURE_LOGS = path.join(FIXTURE_GEMINI_LOGS, "tmp/deadbeefcafe/logs.json");

test("isGeminiSessionFile recognizes chats/session-*.json paths", () => {
  assert.ok(isGeminiSessionFile(FIXTURE_SESSION));
  assert.ok(isGeminiSessionFile("/Users/analyst/.gemini/tmp/hash/chats/session-current.jsonl"));
  assert.ok(isGeminiSessionFile("/Users/analyst/.gemini/tmp/hash/chats/parent-session/child.jsonl"));
  assert.ok(!isGeminiSessionFile("/tmp/session-demo.json"));
});

test("current Gemini JSONL replay preserves exact tool commands/results and rewinds", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-gemini-jsonl-"));
  const chats = path.join(tmp, ".gemini/tmp/project-hash/chats");
  fs.mkdirSync(chats, { recursive: true });
  const sessionPath = path.join(chats, "session-current.jsonl");
  const records = [
    {
      sessionId: "gemini-current-1",
      projectHash: "project-hash",
      startTime: "2026-07-26T10:00:00.000Z",
      lastUpdated: "2026-07-26T10:01:00.000Z",
      kind: "main",
      directories: ["/evidence/case"],
    },
    {
      id: "m-user",
      type: "user",
      timestamp: "2026-07-26T10:00:01.000Z",
      content: [{ text: "Inspect the executable" }],
    },
    {
      id: "m-assistant",
      type: "gemini",
      timestamp: "2026-07-26T10:00:02.000Z",
      content: [{ text: "I will inspect it." }],
      model: "gemini-current",
      tokens: { input: 12, output: 8, total: 20 },
      thoughts: [{ subject: "Plan", description: "Inspect metadata first" }],
      toolCalls: [{
        id: "tool-1",
        name: "run_shell_command",
        args: {
          command: "file '/evidence/case/sample.bin'",
          description: "Identify the executable",
        },
        result: "PE32+ executable",
        status: "success",
        timestamp: "2026-07-26T10:00:03.000Z",
      }],
    },
    {
      id: "rewound-message",
      type: "user",
      timestamp: "2026-07-26T10:00:04.000Z",
      content: "This branch is removed",
    },
    { $rewindTo: "rewound-message" },
    { $set: { lastUpdated: "2026-07-26T10:00:05.000Z" } },
  ];
  fs.writeFileSync(sessionPath, `${records.map((record) => JSON.stringify(record)).join("\n")}\n`);

  try {
    const rows = await extractGeminiSessionJsonlFile(sessionPath, { user: "analyst" });
    assert.equal(rows.length, 4);
    assert.ok(rows.some((row) => row.MessageId === "m-user"));
    assert.ok(!rows.some((row) => row.MessageId === "rewound-message"));
    const call = rows.find((row) => row.RecordType === "tool_call");
    const result = rows.find((row) => row.RecordType === "tool_result");
    assert.ok(call);
    assert.ok(result);
    assert.equal(call.InvokedTool, "run_shell_command");
    assert.equal(call.ToolCommand, "file '/evidence/case/sample.bin'");
    assert.equal(call.ToolDescription, "Identify the executable");
    assert.match(result.FullText, /PE32\+ executable/);
    assert.equal(call.Workspace, "/evidence/case");
    const assistant = rows.find((row) => row.MessageId === "m-assistant");
    assert.equal(assistant.Model, "gemini-current");
    assert.equal(assistant.InputTokens, "12");
    assert.match(assistant.FullText, /Inspect metadata first/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("nested Gemini JSONL sessions are marked as subagent evidence", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-gemini-subagent-"));
  const chats = path.join(tmp, ".gemini/tmp/hash/chats/parent-session");
  fs.mkdirSync(chats, { recursive: true });
  const sessionPath = path.join(chats, "child-session.jsonl");
  fs.writeFileSync(sessionPath, [
    JSON.stringify({
      sessionId: "child-session",
      projectHash: "hash",
      startTime: "2026-07-26T11:00:00.000Z",
      kind: "subagent",
    }),
    JSON.stringify({
      id: "child-msg",
      type: "user",
      timestamp: "2026-07-26T11:00:01.000Z",
      content: "Subagent prompt",
    }),
  ].join("\n"));

  try {
    const rows = await extractGeminiSessionJsonlFile(sessionPath);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].IsSidechain, "true");
    assert.equal(rows[0].ParentId, "parent-session");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("Gemini shell_history preserves exact multiline commands", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-gemini-shell-"));
  const projectDir = path.join(tmp, ".gemini/tmp/project-hash");
  fs.mkdirSync(projectDir, { recursive: true });
  const historyPath = path.join(projectDir, "shell_history");
  fs.writeFileSync(historyPath, "pwd\necho one \\\ntwo\n");

  try {
    assert.ok(isGeminiShellHistoryFile(historyPath));
    const rows = extractGeminiShellHistoryFile(historyPath);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].ToolCommand, "pwd");
    assert.equal(rows[1].ToolCommand, "echo one  two");
    assert.equal(rows[1].InvokedTool, "run_shell_command");
    assert.equal(rows[1].Workspace, "project-hash");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("extractGeminiSessionFile parses user and gemini messages", () => {
  const rows = extractGeminiSessionFile(FIXTURE_SESSION, { user: "analyst" });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].Role, "user");
  assert.equal(rows[0].User, "analyst");
  assert.equal(rows[0].Tool, "Gemini CLI");
  assert.equal(rows[1].Role, "assistant");
  assert.equal(rows[1].Model, "gemini-2.0-flash");
  assert.equal(rows[1].InputTokens, "42");
  assert.match(rows[1].Summary, /Reasoning present/);
  assert.equal(rows[0].SessionId, "sess-gemini-demo-1");
  assert.equal(rows[0].Workspace, "deadbeef");
});

test("extractGeminiCliDir reads all sessions under .gemini/tmp", async () => {
  const rows = await extractGeminiCliDir(FIXTURE_GEMINI, { host: "HOST1" });
  assert.ok(rows.length >= 2);
  assert.ok(rows.every((r) => r.RecordId));
  assert.equal(rows[0].Host, "HOST1");
});

test("isGeminiCliRoot and countGeminiSessions", () => {
  assert.ok(isGeminiCliRoot(FIXTURE_GEMINI));
  assert.ok(countGeminiSessions(FIXTURE_GEMINI) >= 1);
});

test("extractGeminiCliPath accepts a single session file", async () => {
  const rows = await extractGeminiCliPath(FIXTURE_SESSION);
  assert.equal(rows.length, 2);
});

test("isGeminiLogsFile and extractGeminiLogsFile parse tmp/logs.json", () => {
  assert.ok(isGeminiLogsFile(FIXTURE_LOGS));
  assert.ok(!isGeminiLogsFile(FIXTURE_SESSION));
  const rows = extractGeminiLogsFile(FIXTURE_LOGS);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].Role, "user");
  assert.match(rows[0].Summary, /open ports/);
  assert.equal(rows[1].Role, "assistant");
  assert.equal(rows[0].SessionId, "sess-logs-demo-1");
});

test("extractGeminiCliDir reads legacy logs.json under .gemini/tmp", async () => {
  assert.ok(isGeminiCliRoot(FIXTURE_GEMINI_LOGS));
  const rows = await extractGeminiCliDir(FIXTURE_GEMINI_LOGS);
  assert.equal(rows.length, 2);
  assert.equal(countGeminiSessions(FIXTURE_GEMINI_LOGS), 1);
});

test("extractGeminiSessionFile includes system and error message types", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-gemini-"));
  const chats = path.join(tmp, "chats");
  fs.mkdirSync(chats, { recursive: true });
  const sessionPath = path.join(chats, "session-syserr.json");
  fs.writeFileSync(sessionPath, JSON.stringify({
    sessionId: "s-err",
    projectHash: "abc",
    startTime: "2026-03-01T12:00:00.000Z",
    messages: [
      { type: "system", content: "System prompt", timestamp: "2026-03-01T12:00:01.000Z" },
      { type: "error", error: "Rate limited", timestamp: "2026-03-01T12:00:02.000Z" },
    ],
  }));
  const rows = extractGeminiSessionFile(sessionPath);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].Role, "system");
  assert.equal(rows[1].RecordType, "error");
  assert.match(rows[1].Summary, /Rate limited/);
  assert.equal(rows[0].LineNumber, "1");
  fs.rmSync(tmp, { recursive: true, force: true });
});
