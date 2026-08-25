"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  defaultGrokHome,
  isGrokBuildRoot,
  resolveGrokHome,
  isGrokBuildArtifactFile,
  listGrokSessionDirs,
  countGrokDataFiles,
  parseGrokPromptHistoryLine,
  extractGrokBuildDir,
  extractGrokBuildPath,
} = require("../electron/parsers/ai-history/grok-build");
const { detectAiHistoryImport, planImportPaths } = require("../electron/parsers/ai-history-import");

const FIXTURE_GROK = path.join(__dirname, "fixtures/ai-history/grok/.grok");
const WORKSPACE = path.join(FIXTURE_GROK, "sessions/%2Ftmp%2Fgrok-demo");
const SESSION = path.join(WORKSPACE, "grok-session-1");

test("Grok Build root discovery recognizes the official session layout", () => {
  assert.ok(defaultGrokHome().endsWith(".grok") || process.env.GROK_HOME);
  assert.equal(isGrokBuildRoot(FIXTURE_GROK), true);
  assert.equal(resolveGrokHome(path.join(SESSION, "updates.jsonl")), FIXTURE_GROK);
  assert.equal(isGrokBuildArtifactFile(path.join(SESSION, "summary.json")), true);
  assert.equal(listGrokSessionDirs(FIXTURE_GROK).length, 1);
  assert.equal(countGrokDataFiles(FIXTURE_GROK), 4);
});

test("direct Grok shell history preserves the exact command", () => {
  const row = parseGrokPromptHistoryLine({
    timestamp: "2026-07-26T10:00:02.000Z",
    session_id: "grok-session-1",
    prompt: "whoami && id",
    is_bash: true,
  }, "prompt_history.jsonl", { user: "analyst" });
  assert.equal(row.Tool, "Grok Build");
  assert.equal(row.RecordType, "shell_command");
  assert.equal(row.InvokedTool, "shell");
  assert.equal(row.ToolCommand, "whoami && id");
  assert.equal(row.User, "analyst");
});

test("Grok updates parse exact run_terminal_command input and completion output", async () => {
  const rows = await extractGrokBuildDir(FIXTURE_GROK, { user: "analyst", host: "HOST1" });
  const call = rows.find((row) => row.RecordType === "tool_call");
  const result = rows.find((row) => row.RecordType === "tool_result");
  assert.ok(call);
  assert.equal(call.InvokedTool, "run_terminal_command");
  assert.equal(call.ToolCommand, "printf '%s\\n' \"quoted value\"");
  assert.equal(call.ToolDescription, "Print a quoted value");
  assert.equal(call.ToolInput, "{\"command\":\"printf '%s\\\\n' \\\"quoted value\\\"\",\"description\":\"Print a quoted value\"}");
  assert.ok(result);
  assert.equal(result.ParentId, "call-shell-1");
  assert.equal(result.ToolCommand, call.ToolCommand);
  assert.match(result.FullText, /Exit code: 0/);
  assert.match(result.FullText, /quoted value/);
  assert.ok(rows.some((row) => row.RecordType === "file_hunk_added"));
  assert.ok(rows.some((row) => row.RecordType === "turn_completed" && row.InputTokens === "123"));
  assert.ok(rows.every((row) => row.Tool === "Grok Build"));
  assert.ok(rows.every((row) => row.RecordId));
});

test("Grok prompt history dedupes against timestamped session messages", async () => {
  const rows = await extractGrokBuildDir(FIXTURE_GROK);
  assert.equal(rows.filter((row) => row.Summary === "Inspect the suspicious process tree").length, 1);
  assert.ok(rows.some((row) => row.RecordType === "shell_command" && row.ToolCommand === "whoami && id"));
});

test("Grok Build import detection consolidates collected artifacts", async () => {
  assert.equal(detectAiHistoryImport(FIXTURE_GROK)?.tool, "grok-build");
  assert.equal(detectAiHistoryImport(path.join(SESSION, "updates.jsonl"))?.tool, "grok-build");
  const planned = planImportPaths([
    path.join(WORKSPACE, "prompt_history.jsonl"),
    path.join(SESSION, "updates.jsonl"),
  ]);
  assert.equal(planned.length, 1);
  assert.equal(planned[0].opts.aiHistoryTool, "grok-build");
  assert.equal(planned[0].path, FIXTURE_GROK);

  const single = await extractGrokBuildPath(path.join(SESSION, "updates.jsonl"));
  assert.ok(single.some((row) => row.ToolCommand === "printf '%s\\n' \"quoted value\""));
});
