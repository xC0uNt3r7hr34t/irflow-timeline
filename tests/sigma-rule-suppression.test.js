const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  activeSuppressedRuleIds,
  loadRuleSuppressions,
  saveRuleSuppressions,
  syncHayabusaNoisyRules,
} = require("../electron/analyzers/sigma/rule-suppression");

test("rule suppression store includes defaults and persists analyst suppressions", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rule-suppression-"));
  const previous = process.env.TLE_USER_DATA_PATH;
  process.env.TLE_USER_DATA_PATH = root;
  t.after(() => {
    if (previous === undefined) delete process.env.TLE_USER_DATA_PATH;
    else process.env.TLE_USER_DATA_PATH = previous;
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  });

  const defaults = loadRuleSuppressions();
  assert.ok(defaults.some((entry) => /NotPetya/i.test(entry.title)));

  const saved = saveRuleSuppressions([
    ...defaults,
    {
      ruleId: "11111111-1111-1111-1111-111111111111",
      title: "Noisy test rule",
      scopeType: "case",
      scope: "Case A",
      reason: "Known lab tool",
      enabled: true,
    },
  ]);

  assert.ok(saved.some((entry) => entry.title === "Noisy test rule" && entry.scopeType === "case"));
  assert.ok(activeSuppressedRuleIds(saved).includes("11111111-1111-1111-1111-111111111111"));
});

test("rule suppression sync writes enabled global rules to Hayabusa noisy_rules.txt", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rule-suppression-sync-"));
  const configDir = path.join(root, "rules", "config");
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(path.join(configDir, "noisy_rules.txt"), [
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa # existing",
    "dddddddd-dddd-dddd-dddd-dddddddddddd # old managed noisy line",
    "",
  ].join("\n"), "utf8");
  t.after(() => {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  });

  const result = syncHayabusaNoisyRules([
    {
      ruleId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      title: "Global noisy rule",
      scopeType: "global",
      scope: "all cases",
      reason: "Too broad",
      enabled: true,
    },
    {
      ruleId: "cccccccc-cccc-cccc-cccc-cccccccccccc",
      title: "Case-only rule",
      scopeType: "case",
      scope: "Case A",
      reason: "Only this case",
      enabled: true,
    },
    {
      ruleId: "dddddddd-dddd-dddd-dddd-dddddddddddd",
      title: "Disabled rule",
      scopeType: "global",
      scope: "all cases",
      reason: "Disabled entry",
      enabled: false,
    },
  ], { configDir });

  assert.equal(result.synced, true);
  const contents = fs.readFileSync(path.join(configDir, "noisy_rules.txt"), "utf8");
  assert.match(contents, /aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/);
  assert.match(contents, /bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/);
  assert.doesNotMatch(contents, /cccccccc-cccc-cccc-cccc-cccccccccccc/);
  assert.doesNotMatch(contents, /dddddddd-dddd-dddd-dddd-dddddddddddd/);
});
