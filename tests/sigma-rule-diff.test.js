const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  diffRuleSnapshots,
  getHayabusaRulesDir,
  snapshotRuleDirectory,
} = require("../electron/analyzers/sigma/rule-diff");

function writeFile(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

test("Hayabusa rule diff reports added, removed, changed, current count, and timestamps", (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rule-diff-"));
  const binPath = path.join(tempDir, "hayabusa");
  const rulesDir = getHayabusaRulesDir(binPath);

  t.after(() => {
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });

  writeFile(path.join(rulesDir, "windows", "process_creation", "rule-a.yml"), "title: Original A\n");
  writeFile(path.join(rulesDir, "windows", "process_creation", "rule-b.yaml"), "title: Original B\n");
  writeFile(path.join(rulesDir, "config", "level_tuning.yml"), "level: informational\n");
  writeFile(path.join(rulesDir, "README.txt"), "not a rule\n");

  const before = snapshotRuleDirectory(rulesDir);
  assert.equal(before.exists, true);
  assert.equal(before.count, 2);
  assert.ok(before.latestRuleMtime);

  fs.unlinkSync(path.join(rulesDir, "windows", "process_creation", "rule-b.yaml"));
  writeFile(path.join(rulesDir, "windows", "process_creation", "rule-a.yml"), "title: Changed A\n");
  writeFile(path.join(rulesDir, "windows", "account_management", "rule-c.yml"), "title: Added C\n");
  writeFile(path.join(rulesDir, "config", "new_config_rule.yml"), "title: Excluded config\n");

  const after = snapshotRuleDirectory(rulesDir);
  const diff = diffRuleSnapshots(before, after, { sampleLimit: 10 });

  assert.equal(diff.beforeCount, 2);
  assert.equal(diff.currentRuleCount, 2);
  assert.equal(diff.addedCount, 1);
  assert.equal(diff.removedCount, 1);
  assert.equal(diff.changedCount, 1);
  assert.deepEqual(diff.addedRules, ["windows/account_management/rule-c.yml"]);
  assert.deepEqual(diff.removedRules, ["windows/process_creation/rule-b.yaml"]);
  assert.deepEqual(diff.changedRules, ["windows/process_creation/rule-a.yml"]);
  assert.ok(diff.lastUpdateTime);
  assert.ok(diff.latestRuleMtime);
  assert.equal(diff.rulesDir, rulesDir);
});

test("rule directory snapshot handles missing directories", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rule-diff-missing-"));
  const missingDir = path.join(tempDir, "rules");

  try {
    const snapshot = snapshotRuleDirectory(missingDir);
    assert.equal(snapshot.exists, false);
    assert.equal(snapshot.count, 0);
    assert.deepEqual(snapshot.files, {});
  } finally {
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
  }
});
