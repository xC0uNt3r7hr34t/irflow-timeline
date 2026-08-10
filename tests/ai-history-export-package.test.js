"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  sanitizeExportBaseName,
  sha256File,
  enrichSourceManifest,
  buildPackageManifest,
  buildSourcesOnlyManifest,
} = require("../electron/parsers/ai-history/export-package");

test("sanitizeExportBaseName strips unsafe characters", () => {
  assert.equal(sanitizeExportBaseName("Claude Code AI History (42)"), "Claude_Code_AI_History_42");
});

test("sha256File hashes file contents", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-hash-"));
  const filePath = path.join(tmp, "sample.txt");
  fs.writeFileSync(filePath, "hello ai history");
  const hash = await sha256File(filePath);
  assert.equal(hash.length, 64);
  assert.match(hash, /^[a-f0-9]+$/);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("enrichSourceManifest records exists and hash", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-manifest-"));
  const filePath = path.join(tmp, "history.jsonl");
  fs.writeFileSync(filePath, '{"display":"test"}\n');
  const { sources, hashedFileCount } = await enrichSourceManifest([{ value: filePath, count: 3 }]);
  assert.equal(sources.length, 1);
  assert.equal(sources[0].rowCount, 3);
  assert.equal(sources[0].exists, true);
  assert.ok(sources[0].sha256);
  assert.equal(hashedFileCount, 1);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("buildPackageManifest includes format version and tools", () => {
  const m = buildPackageManifest({
    tabName: "AI Query History",
    sourceFormat: "ai-history-claude-code",
    totalRows: 100,
    exportedRows: 50,
    filtersApplied: true,
    sources: [{ path: "/x/history.jsonl", rowCount: 50, exists: true }],
    hashedFileCount: 1,
    hashTruncated: false,
    toolBreakdown: [{ tool: "Claude Code", rowCount: 50 }],
  });
  assert.equal(m.format, "irflow-ai-history-package");
  assert.equal(m.formatVersion, 1);
  assert.equal(m.rowCount.exported, 50);
  assert.equal(m.toolBreakdown[0].tool, "Claude Code");
});

test("buildSourcesOnlyManifest omits exported row count slice", () => {
  const m = buildSourcesOnlyManifest({
    tabName: "AI Query History",
    sourceFormat: "ai-history-profile",
    totalRows: 100,
    filtersApplied: false,
    sources: [{ path: "/x/history.jsonl", rowCount: 100, exists: true }],
    hashedFileCount: 1,
    hashTruncated: false,
    toolBreakdown: [{ tool: "Claude Code", rowCount: 100 }],
  });
  assert.equal(m.format, "irflow-ai-history-sources-only");
  assert.equal(m.rowCountInScope, 100);
  assert.equal(m.rowCount, undefined);
  assert.equal(m.sources.length, 1);
});
