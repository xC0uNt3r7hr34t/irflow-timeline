"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  authorizeAiScanTarget,
  authorizeAiArtifactPick,
  assertAiReadablePath,
  assertExtractRootsAuthorized,
} = require("../electron/parsers/ai-history/path-auth");

test("authorizeAiScanTarget allows nested artifact paths", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ai-auth-"));
  const claude = path.join(root, "Users", "alice", ".claude");
  fs.mkdirSync(claude, { recursive: true });

  authorizeAiScanTarget(root);
  assert.doesNotThrow(() => assertAiReadablePath(claude));
  assert.doesNotThrow(() => assertExtractRootsAuthorized(
    [{ tool: "claude-code", path: claude }],
    root,
  ));

  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ai-out-"));
  assert.throws(() => assertAiReadablePath(outside));

  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});

test("authorizeAiArtifactPick grants read on picked file tree", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ai-pick-"));
  const codex = path.join(root, ".codex");
  fs.mkdirSync(codex, { recursive: true });
  fs.writeFileSync(path.join(codex, "history.jsonl"), "");

  authorizeAiArtifactPick(codex);
  assert.doesNotThrow(() => assertAiReadablePath(path.join(codex, "history.jsonl")));

  fs.rmSync(root, { recursive: true, force: true });
});
