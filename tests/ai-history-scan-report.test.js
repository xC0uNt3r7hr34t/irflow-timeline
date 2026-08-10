"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");

const { buildEmptyAiScanReport, probeCollectionLayout } = require("../electron/parsers/ai-history/scan-report");

test("buildEmptyAiScanReport includes expected path hints for folder mode", () => {
  const report = buildEmptyAiScanReport({
    scanMode: "folder",
    scanRoot: "/tmp/kape-out",
    scanned: 1200,
    hitsFound: 0,
  });
  assert.match(report.summary, /No AI assistant artifacts/i);
  assert.match(report.detail, /Users\\/);
  assert.match(report.detail, /\.claude/);
  assert.equal(report.suggestAiRescan, true);
  assert.ok(Array.isArray(report.checklist) && report.checklist.length >= 1);
  assert.match(report.detail, /Scan AI Artifacts/i);
});

test("buildEmptyAiScanReport flags incomplete collection when Users exists", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ai-empty-"));
  try {
    fs.mkdirSync(path.join(tmp, "Users", "Alice"), { recursive: true });
    const report = buildEmptyAiScanReport({
      scanMode: "folder",
      scanRoot: tmp,
      scanned: 50,
      hitsFound: 0,
    });
    assert.equal(report.collectionIncomplete, true);
    assert.ok(report.checklist.some((s) => s.platform === "windows"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("probeCollectionLayout detects Users directory", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ai-scan-"));
  try {
    fs.mkdirSync(path.join(tmp, "Users", "Alice"), { recursive: true });
    const probe = probeCollectionLayout(tmp);
    assert.equal(probe.hasUsersDir, true);
    assert.ok(probe.userSample.includes("Alice"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
