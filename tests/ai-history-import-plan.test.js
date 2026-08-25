"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const {
  planImportPaths,
  needsScopeForAiImport,
} = require("../electron/parsers/ai-history-import");

test("needsScopeForAiImport is true for Claude directory only", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ai-scope-"));
  try {
    const claude = path.join(tmp, ".claude");
    fs.mkdirSync(claude, { recursive: true });
    assert.equal(needsScopeForAiImport("claude-code", claude), true);
    assert.equal(needsScopeForAiImport("chatgpt", claude), false);
    const jsonl = path.join(claude, "history.jsonl");
    fs.writeFileSync(jsonl, "{}\n");
    assert.equal(needsScopeForAiImport("claude-code", jsonl), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("planImportPaths flags scope choice for .claude folder", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ai-plan-"));
  try {
    const claude = path.join(tmp, ".claude");
    fs.mkdirSync(path.join(claude, "projects", "p"), { recursive: true });
    fs.writeFileSync(path.join(claude, "history.jsonl"), '{"display":"hi","timestamp":1}\n');
    const planned = planImportPaths([claude]);
    assert.equal(planned.length, 1);
    assert.equal(planned[0].opts.aiHistoryTool, "claude-code");
    assert.equal(planned[0].needsScopeChoice, true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
