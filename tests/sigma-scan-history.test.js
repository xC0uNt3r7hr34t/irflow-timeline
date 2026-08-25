const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { SigmaResultStore } = require("../electron/analyzers/sigma/result-store");

function loadHistoryModule(userDataPath) {
  const modulePath = require.resolve("../electron/analyzers/sigma/scan-history");
  delete require.cache[modulePath];
  process.env.TLE_USER_DATA_PATH = userDataPath;
  return require("../electron/analyzers/sigma/scan-history");
}

test("scan history persists metadata, result stores, reports, packages, and deletion", async (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-history-user-"));
  const sourceDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-history-source-"));
  const exportDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-history-export-"));
  const sourceDbPath = path.join(sourceDir, "results.sqlite");
  const previousUserData = process.env.TLE_USER_DATA_PATH;
  const scanHistory = loadHistoryModule(userDataPath);

  t.after(() => {
    if (previousUserData === undefined) delete process.env.TLE_USER_DATA_PATH;
    else process.env.TLE_USER_DATA_PATH = previousUserData;
    try { SigmaResultStore.destroy(sourceDbPath); } catch {}
    try { fs.rmSync(userDataPath, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(exportDir, { recursive: true, force: true }); } catch {}
  });

  let store;
  try {
    store = new SigmaResultStore({ dbPath: sourceDbPath });
  } catch (err) {
    if (err?.code === "ERR_DLOPEN_FAILED") {
      t.skip("better-sqlite3 native module is not built for this Node runtime");
      return;
    }
    throw err;
  }

  store.addRows([
    {
      Timestamp: "2026-01-01T00:00:01Z",
      Computer: "HOST1",
      RuleID: "rule-1",
      RuleTitle: "Suspicious Process",
      Level: "high",
      SourceTabId: "tab-1",
      SourceRowId: 7,
    },
  ]);
  store.finalize({ engine: "test" });
  store.close();

  const saved = scanHistory.saveScanHistory({
    jobId: "job-1",
    resultDbPath: sourceDbPath,
    htmlReport: "<html><body>report</body></html>",
    metadata: {
      scanType: "tab",
      engine: "IRFlow Sigma Engine",
      targetName: "Security.evtx.csv",
      sourceTabId: "tab-1",
      levels: ["high"],
      statuses: ["stable"],
      ruleLastUpdate: "2026-01-01T00:00:00.000Z",
      matches: [{ title: "Suspicious Process", level: "high", matchCount: 1 }],
      stats: { matchedRules: 1, totalMatches: 1, totalRules: 10, rowsScanned: 50 },
      warnings: ["1 disabled/noisy rule was skipped by Detection Settings suppression."],
      eventRowCount: 1,
    },
  });

  assert.ok(saved.id);
  assert.equal(saved.hasResultStore, true);
  assert.equal(saved.hasHtmlReport, true);
  assert.equal(saved.matchedRules, 1);
  assert.equal(saved.warningCount, 1);
  assert.ok(saved.resultStoreSizeBytes > 0);

  const listed = scanHistory.listScanHistory();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].targetName, "Security.evtx.csv");
  assert.equal(listed[0].totalMatches, 1);
  assert.equal(listed[0].warningCount, 1);
  assert.ok(listed[0].resultStoreSizeBytes > 0);

  const full = scanHistory.getScanHistory(saved.id);
  assert.ok(full.resultDbPath);
  assert.deepEqual(full.warnings, ["1 disabled/noisy rule was skipped by Detection Settings suppression."]);
  assert.ok(fs.existsSync(full.resultDbPath));
  assert.equal(scanHistory.readHtmlReport(saved.id), "<html><body>report</body></html>");

  const triage = scanHistory.updateScanTriage(saved.id, {
    reviewedRules: { "rule-1": "2026-01-01T00:10:00.000Z" },
    falsePositiveRules: { "rule-2": true },
  });
  assert.equal(triage.updated, true);
  assert.deepEqual(scanHistory.getScanHistory(saved.id).triageState.reviewedRules, { "rule-1": "2026-01-01T00:10:00.000Z" });
  assert.ok(scanHistory.getScanHistory(saved.id).triageState.falsePositiveRules["rule-2"]);

  const reopened = SigmaResultStore.open(full.resultDbPath);
  try {
    assert.deepEqual(reopened.getPreview(1).map((row) => row.RuleTitle), ["Suspicious Process"]);
    assert.deepEqual(reopened.getSourceRowsForRule({ ruleId: "rule-1" }), [{ tabId: "tab-1", rowId: 7 }]);
  } finally {
    reopened.close();
  }

  assert.deepEqual(scanHistory.getScanHistorySettings(), { retentionDays: 0 });
  assert.deepEqual(scanHistory.saveScanHistorySettings({ retentionDays: 30 }), { retentionDays: 30 });
  assert.deepEqual(scanHistory.getScanHistorySettings(), { retentionDays: 30 });

  const exported = await scanHistory.exportScanPackage(saved.id, exportDir);
  assert.equal(exported.exported, true);
  assert.ok(fs.existsSync(path.join(exported.path, "metadata.json")));
  assert.ok(fs.existsSync(path.join(exported.path, "results.sqlite")));
  assert.ok(fs.existsSync(path.join(exported.path, "detections.csv")));
  assert.ok(fs.existsSync(path.join(exported.path, "detections.json")));
  assert.ok(fs.existsSync(path.join(exported.path, "report.html")));

  assert.deepEqual(scanHistory.deleteScanHistory(saved.id), { deleted: true, id: saved.id });
  assert.equal(scanHistory.listScanHistory().length, 0);
  assert.equal(fs.existsSync(full.resultDbPath), false);
});

test("scan history prunes records older than retention", (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-history-prune-"));
  const previousUserData = process.env.TLE_USER_DATA_PATH;
  const scanHistory = loadHistoryModule(userDataPath);

  t.after(() => {
    if (previousUserData === undefined) delete process.env.TLE_USER_DATA_PATH;
    else process.env.TLE_USER_DATA_PATH = previousUserData;
    try { fs.rmSync(userDataPath, { recursive: true, force: true }); } catch {}
  });

  scanHistory.saveScanHistory({
    metadata: {
      id: "old-scan",
      createdAt: new Date(Date.now() - 10 * 86400000).toISOString(),
      targetName: "old",
      stats: { matchedRules: 0, totalMatches: 0 },
    },
  });
  scanHistory.saveScanHistory({
    metadata: {
      id: "new-scan",
      createdAt: new Date().toISOString(),
      targetName: "new",
      stats: { matchedRules: 0, totalMatches: 0 },
    },
  });

  const pruned = scanHistory.pruneScanHistory({ retentionDays: 7 });
  assert.equal(pruned.deleted, 1);
  assert.equal(pruned.kept, 1);
  assert.deepEqual(scanHistory.listScanHistory().map((r) => r.id), ["new-scan"]);
});

test("scan history package includes reproducibility metadata and config files", async (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-history-repro-"));
  const exportDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-history-repro-export-"));
  const configDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-history-repro-config-"));
  const configPath = path.join(configDir, "noisy_rules.txt");
  const previousUserData = process.env.TLE_USER_DATA_PATH;
  const scanHistory = loadHistoryModule(userDataPath);

  fs.writeFileSync(configPath, "NotPetya Ransomware Activity\n", "utf8");

  t.after(() => {
    if (previousUserData === undefined) delete process.env.TLE_USER_DATA_PATH;
    else process.env.TLE_USER_DATA_PATH = previousUserData;
    try { fs.rmSync(userDataPath, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(exportDir, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(configDir, { recursive: true, force: true }); } catch {}
  });

  const saved = scanHistory.saveScanHistory({
    metadata: {
      id: "repro-scan",
      scanType: "evtx-dir",
      engine: "Hayabusa",
      targetName: "Security.evtx",
      commandLine: "/usr/local/bin/hayabusa csv-timeline -d /case -o /tmp/out.csv",
      hayabusaVersion: "v3.8.1",
      hayabusaRulesSnapshotHash: "hayabusa-rules-hash",
      ruleSnapshotHash: "js-rule-hash",
      ruleUpdateLog: ["downloaded SigmaHQ @ abc123"],
      hayabusaRuleUpdateLog: ["Hayabusa rules updated"],
      ruleCompatibilityReport: { parsed: 10, compatible: 8, skipped: 1, unsupportedRules: 2 },
      configFiles: [{ path: configPath, relativePath: "noisy_rules.txt", sha256: "hash" }],
      stats: { matchedRules: 0, totalMatches: 0 },
    },
  });

  const full = scanHistory.getScanHistory(saved.id);
  assert.equal(full.commandLine.includes("hayabusa csv-timeline"), true);
  assert.equal(full.hayabusaVersion, "v3.8.1");
  assert.equal(full.ruleSnapshotHash, "js-rule-hash");
  assert.equal(full.hayabusaRulesSnapshotHash, "hayabusa-rules-hash");

  const exported = await scanHistory.exportScanPackage(saved.id, exportDir);
  assert.equal(exported.exported, true);
  assert.ok(fs.existsSync(path.join(exported.path, "metadata.json")));
  assert.ok(fs.existsSync(path.join(exported.path, "scan-command.txt")));
  assert.ok(fs.existsSync(path.join(exported.path, "rule-update.log")));
  assert.ok(fs.existsSync(path.join(exported.path, "hayabusa-rule-update.log")));
  assert.ok(fs.existsSync(path.join(exported.path, "rule-compatibility.json")));
  assert.ok(fs.existsSync(path.join(exported.path, "config", "noisy_rules.txt")));
});
