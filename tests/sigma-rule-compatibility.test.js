const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { parseRulesDetailed, parseDirectoryDetailed } = require("../electron/analyzers/sigma/rule-parser");
const { annotateRuleCompatibility, buildRuleCompatibilityReport } = require("../electron/analyzers/sigma/rule-compatibility");

test("Sigma parser reads all YAML documents in a multi-document rule file", () => {
  const yaml = [
    "title: First Rule",
    "id: first-rule",
    "logsource:",
    "  product: windows",
    "  category: process_creation",
    "detection:",
    "  selection:",
    "    Image|endswith: '\\\\cmd.exe'",
    "  condition: selection",
    "---",
    "title: Second Rule",
    "id: second-rule",
    "logsource:",
    "  product: windows",
    "  service: security",
    "detection:",
    "  selection:",
    "    EventID: 4624",
    "  condition: selection",
  ].join("\n");

  const parsed = parseRulesDetailed(yaml, "multi.yml");
  assert.equal(parsed.rules.length, 2);
  assert.equal(parsed.report.documentsScanned, 2);
  assert.equal(parsed.report.parsed, 2);
  assert.deepEqual(parsed.rules.map((rule) => rule.id), ["first-rule", "second-rule"]);
});

test("Sigma compatibility report counts skipped YAML docs and unsupported features", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-compat-"));
  try {
    fs.writeFileSync(path.join(root, "mixed.yml"), [
      "title: Compatible Rule",
      "id: compatible-rule",
      "logsource:",
      "  product: windows",
      "  category: process_creation",
      "detection:",
      "  selection:",
      "    Image|contains: powershell",
      "  condition: selection",
      "---",
      "title: Unsupported Modifier",
      "id: unsupported-modifier-rule",
      "logsource:",
      "  product: windows",
      "  category: process_creation",
      "detection:",
      "  selection:",
      "    Image|foobar: powershell",
      "  condition: selection",
      "---",
      "title: Unsupported Condition",
      "id: unsupported-condition-rule",
      "logsource:",
      "  product: windows",
      "  category: process_creation",
      "detection:",
      "  selection:",
      "    Image|contains: powershell",
      "  condition: selection near filter by CommandLine",
      "---",
      "title: Linux Rule",
      "id: linux-rule",
      "logsource:",
      "  product: linux",
      "detection:",
      "  selection:",
      "    Image|contains: bash",
      "  condition: selection",
      "---",
      "not_a_sigma_rule: true",
    ].join("\n"));

    const parsed = parseDirectoryDetailed(root);
    const rules = parsed.rules.map((rule) => annotateRuleCompatibility(rule));
    const report = buildRuleCompatibilityReport(rules, parsed.report);

    assert.equal(parsed.rules.length, 4);
    assert.equal(report.parsed, 4);
    assert.equal(report.skipped, 1);
    assert.equal(report.compatible, 1);
    assert.equal(report.unsupportedModifierRules, 1);
    assert.equal(report.unsupportedConditionRules, 1);
    assert.equal(report.unsupportedLogsourceRules, 1);
    assert.equal(report.byModifier.foobar, 1);
    assert.ok(report.byCondition.near >= 1);
    assert.ok(report.byLogsource["product:linux"] >= 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
