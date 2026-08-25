const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { validateEvtxScanRequest } = require("../electron/analyzers/sigma/scan-preflight");

function writeFile(filePath, content = "") {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

test("EVTX scan preflight accepts a valid directory and summarizes setup", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-preflight-"));
  const rulesDir = path.join(root, "rules");
  const geoDir = path.join(root, "geoip");
  const configPath = path.join(root, "config.yml");

  t.after(() => {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  });

  writeFile(path.join(root, "Security.evtx"), "evtx bytes");
  writeFile(path.join(rulesDir, "windows", "rule.yml"), "title: Test Rule\n");
  writeFile(path.join(geoDir, "GeoLite2-City.mmdb"), "mmdb");
  writeFile(configPath, "rules:\n  - id: test\n");

  const result = validateEvtxScanRequest(root, {
    outputMode: "csv",
    profile: "verbose",
    ruleSet: "core",
    rulesPath: rulesDir,
    rulesConfig: configPath,
    geoIpDir: geoDir,
    includeEids: ["4624", "4688"],
  });

  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.evtxFileCount, 1);
  assert.equal(result.summary.customRuleCount, 1);
  assert.equal(result.summary.geoIpFileCount, 1);
});

test("EVTX scan preflight blocks invalid scan setup", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-preflight-invalid-"));
  const emptyRulesDir = path.join(root, "empty-rules");
  const badConfig = path.join(root, "bad.yml");

  t.after(() => {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  });

  fs.mkdirSync(emptyRulesDir, { recursive: true });
  writeFile(badConfig, "rules: [");

  const result = validateEvtxScanRequest(root, {
    outputMode: "xml",
    profile: "unknown",
    ruleSet: "bad-set",
    rulesPath: emptyRulesDir,
    rulesConfig: badConfig,
    includeEids: ["4624", "abc"],
    levels: [],
    statuses: [],
    timelineStart: "2026-02-01 00:00:00",
    timelineEnd: "2026-01-01 00:00:00",
  });

  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => /No \.evtx files/i.test(e)));
  assert.ok(result.errors.some((e) => /Unsupported output mode/i.test(e)));
  assert.ok(result.errors.some((e) => /Unsupported Hayabusa output profile/i.test(e)));
  assert.ok(result.errors.some((e) => /Unsupported rule set/i.test(e)));
  assert.ok(result.errors.some((e) => /Custom rules directory does not contain/i.test(e)));
  assert.ok(result.errors.some((e) => /Rules config YAML is invalid/i.test(e)));
  assert.ok(result.errors.some((e) => /Invalid include Event ID values: abc/i.test(e)));
  assert.ok(result.errors.some((e) => /severity level/i.test(e)));
  assert.ok(result.errors.some((e) => /rule status/i.test(e)));
  assert.ok(result.errors.some((e) => /Timeline start must be earlier/i.test(e)));
});

test("EVTX scan preflight summarizes preset and warns on Hayabusa/rule setup risks", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-preflight-risk-"));
  const rulesDir = path.join(root, "rules");
  const externalConfig = path.join(root, "outside-config", "level_tuning.yml");
  const oldUpdate = new Date(Date.now() - 45 * 86400000).toISOString();

  t.after(() => {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  });

  writeFile(path.join(root, "Security.evtx"), "evtx bytes");
  writeFile(path.join(rulesDir, "rule.yml"), "title: Test Rule\n");
  writeFile(externalConfig, "rules:\n  - id: test\n");

  const result = validateEvtxScanRequest(root, {
    presetName: "Full hunt",
    presetSummary: "all severities | all statuses | all EVTX",
    outputMode: "csv",
    profile: "verbose",
    ruleSet: "all",
    eidFilter: false,
    provenRules: false,
    levels: ["critical", "high", "medium"],
    statuses: ["stable", "test"],
    rulesPath: rulesDir,
    rulesConfig: externalConfig,
    hayabusaStatus: { installed: true, version: "v3.8.1" },
    hayabusaRuleState: {
      hayabusaRuleCount: 2,
      hayabusaRulesLastUpdate: oldUpdate,
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.summary.presetName, "Full hunt");
  assert.equal(result.summary.presetSummary, "all severities | all statuses | all EVTX");
  assert.deepEqual(result.summary.selectedLevels, ["critical", "high", "medium"]);
  assert.deepEqual(result.summary.selectedStatuses, ["stable", "test"]);
  assert.equal(result.summary.hayabusaInstalled, true);
  assert.equal(result.summary.hayabusaVersion, "v3.8.1");
  assert.equal(result.summary.hayabusaRuleCount, 2);
  assert.equal(result.summary.hayabusaRulesCurrent, false);
  assert.ok(result.warnings.some((w) => /45 days old|appear \d+ days old/i.test(w)));
  assert.ok(result.warnings.some((w) => /Broad All Rules scan without EID filter/i.test(w)));
  assert.ok(result.warnings.some((w) => /not limited to proven rules/i.test(w)));
  assert.ok(result.warnings.some((w) => /outside the selected custom rules directory/i.test(w)));
});
