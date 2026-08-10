"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  scanBrowserAgentHints,
  buildBrowserAgentReportLines,
} = require("../electron/parsers/ai-history/browser-agents");

test("scanBrowserAgentHints finds Chrome profile paths in triage layout", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-browser-"));
  const chrome = path.join(root, "Users", "bob", "AppData", "Local", "Google", "Chrome", "Default", "IndexedDB");
  fs.mkdirSync(chrome, { recursive: true });
  const hits = scanBrowserAgentHints(root, { maxDepth: 14, maxHits: 10 });
  assert.ok(hits.length >= 1);
  const lines = buildBrowserAgentReportLines(hits);
  assert.ok(lines.some((l) => /Browser-side AI/i.test(l)));
  fs.rmSync(root, { recursive: true, force: true });
});
