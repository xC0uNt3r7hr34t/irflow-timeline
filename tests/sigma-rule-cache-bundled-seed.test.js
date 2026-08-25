const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// A minimal but valid Sigma rule the JS parser will accept.
function writeRule(dir, file, id, title) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, file),
    [
      `title: ${title}`,
      `id: ${id}`,
      "status: test",
      "logsource:",
      "    product: windows",
      "    service: security",
      "detection:",
      "    selection:",
      "        EventID: 4688",
      "    condition: selection",
      "level: medium",
      "",
    ].join("\n"),
    "utf8",
  );
}

// Build a fake Electron resources dir: <resources>/hayabusa/rules/sigma/<area>/*.yml
function makeFakeResources() {
  const resources = fs.mkdtempSync(path.join(os.tmpdir(), "tle-resources-"));
  const sigmaDir = path.join(resources, "hayabusa", "rules", "sigma");
  writeRule(path.join(sigmaDir, "builtin"), "rule-a.yml", "aaaaaaaa-0000-0000-0000-000000000001", "Bundled Rule A");
  writeRule(path.join(sigmaDir, "sysmon"), "rule-b.yml", "bbbbbbbb-0000-0000-0000-000000000002", "Bundled Rule B");
  return { resources, sigmaDir };
}

function freshRuleCache() {
  const p = require.resolve("../electron/analyzers/sigma/rule-cache");
  delete require.cache[p];
  return require("../electron/analyzers/sigma/rule-cache");
}

function withEnv(userData, resources, fn) {
  const prevUser = process.env.TLE_USER_DATA_PATH;
  const prevRes = process.env.TLE_RESOURCES_PATH;
  process.env.TLE_USER_DATA_PATH = userData;
  if (resources === null) delete process.env.TLE_RESOURCES_PATH;
  else process.env.TLE_RESOURCES_PATH = resources;
  try {
    return fn();
  } finally {
    if (prevUser === undefined) delete process.env.TLE_USER_DATA_PATH; else process.env.TLE_USER_DATA_PATH = prevUser;
    if (prevRes === undefined) delete process.env.TLE_RESOURCES_PATH; else process.env.TLE_RESOURCES_PATH = prevRes;
  }
}

test("seedBundledRulesIfEmpty populates an empty cache from bundled Hayabusa Sigma rules", () => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "tle-userdata-"));
  const { resources, sigmaDir } = makeFakeResources();
  try {
    withEnv(userData, resources, () => {
      const rc = freshRuleCache();
      assert.equal(rc.getBundledSigmaRulesDir(), sigmaDir);

      const seed = rc.seedBundledRulesIfEmpty();
      assert.equal(seed.seeded, true);
      assert.equal(seed.count, 2);

      const all = rc.getAllRules();
      assert.equal(all.rules.length, 2);
      assert.equal(all.meta.source, "bundled");
      assert.equal(all.meta.bundled, true);

      const status = rc.getCacheStatus();
      assert.equal(status.cachedRuleCount, 2);
      assert.equal(status.source, "bundled");
    });
  } finally {
    fs.rmSync(userData, { recursive: true, force: true });
    fs.rmSync(resources, { recursive: true, force: true });
  }
});

test("getAllRules() auto-seeds from bundled rules when the cache is empty", () => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "tle-userdata-"));
  const { resources } = makeFakeResources();
  try {
    withEnv(userData, resources, () => {
      const rc = freshRuleCache();
      // No explicit seed call — getAllRules() must seed lazily.
      const all = rc.getAllRules();
      assert.equal(all.rules.length, 2);
      // rules.json must have been written so the parse is not repeated.
      assert.ok(fs.existsSync(path.join(userData, "sigma-rules", "rules.json")));
    });
  } finally {
    fs.rmSync(userData, { recursive: true, force: true });
    fs.rmSync(resources, { recursive: true, force: true });
  }
});

test("seedBundledRulesIfEmpty never clobbers an already-populated cache", () => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "tle-userdata-"));
  const { resources } = makeFakeResources();
  try {
    withEnv(userData, resources, () => {
      const rc = freshRuleCache();
      // Pretend a real download already happened.
      const cacheDir = rc.getCacheDir();
      const existing = [{ id: "downloaded-1", title: "Already Downloaded", logsource: {}, detection: {} }];
      fs.writeFileSync(path.join(cacheDir, "rules.json"), JSON.stringify(existing), "utf8");

      const seed = rc.seedBundledRulesIfEmpty();
      assert.equal(seed.seeded, false);
      assert.equal(seed.count, 1);

      const all = rc.getAllRules();
      assert.equal(all.rules.length, 1);
      assert.equal(all.rules[0].id, "downloaded-1");
    });
  } finally {
    fs.rmSync(userData, { recursive: true, force: true });
    fs.rmSync(resources, { recursive: true, force: true });
  }
});

test("seedBundledRulesIfEmpty is a no-op when no bundled rules are present", () => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), "tle-userdata-"));
  try {
    withEnv(userData, null, () => {
      const rc = freshRuleCache();
      assert.equal(rc.getBundledSigmaRulesDir(), null);
      const seed = rc.seedBundledRulesIfEmpty();
      assert.equal(seed.seeded, false);
      assert.equal(seed.count, 0);
      assert.equal(rc.getAllRules().rules.length, 0);
    });
  } finally {
    fs.rmSync(userData, { recursive: true, force: true });
  }
});
