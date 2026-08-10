"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  aiHistoryOpenDialogFilters,
  defaultAiHistoryOpenPath,
  defaultDecodeAiHistoryDialogPath,
} = require("../electron/parsers/ai-history/open-dialog-paths");

test("aiHistoryOpenDialogFilters lists per-tool AI artifact groups", () => {
  const filters = aiHistoryOpenDialogFilters();
  const names = filters.map((f) => f.name).join(" ");
  assert.match(names, /Claude Code/);
  assert.match(names, /ChatGPT Desktop/);
  assert.match(names, /Cursor/);
  assert.match(names, /Copilot/);
  assert.match(names, /Codex/);
  assert.match(names, /Grok Build/);
});

test("defaultAiHistoryOpenPath returns a string path", () => {
  const p = defaultAiHistoryOpenPath();
  assert.ok(typeof p === "string" && p.length > 0);
});

test("defaultDecodeAiHistoryDialogPath returns a path hint per tool", () => {
  for (const tool of [
    "claude-code", "codex", "grok-build", "chatgpt", "gemini-cli", "cursor", "copilot", "windsurf", "continue",
  ]) {
    const p = defaultDecodeAiHistoryDialogPath(tool);
    assert.ok(typeof p === "string" && p.length > 0, tool);
  }
});
