const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

function loadSettingsModule(userDataPath) {
  const modulePath = require.resolve("../electron/analyzers/sigma/detection-settings");
  delete require.cache[modulePath];
  process.env.TLE_USER_DATA_PATH = userDataPath;
  return require("../electron/analyzers/sigma/detection-settings");
}

test("detection settings persist normalized scan defaults", (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-detection-settings-"));
  const previousUserData = process.env.TLE_USER_DATA_PATH;
  const settingsStore = loadSettingsModule(userDataPath);

  t.after(() => {
    if (previousUserData === undefined) delete process.env.TLE_USER_DATA_PATH;
    else process.env.TLE_USER_DATA_PATH = previousUserData;
    try { fs.rmSync(userDataPath, { recursive: true, force: true }); } catch {}
  });

  assert.equal(settingsStore.loadDetectionSettings().ruleSet, "all");
  const saved = settingsStore.saveDetectionSettings({
    ruleSet: "core+",
    enableNoisy: true,
    geoIpDir: "/cases/geoip",
    outputMode: "jsonl",
    profile: "super-verbose",
    rulesPath: "/cases/rules",
    rulesConfig: "/cases/config/default.yaml",
    hayabusaMinSeverity: "high",
    includeEids: "4624,4625",
  });
  assert.equal(saved.ruleSet, "core+");
  assert.equal(saved.enableNoisy, true);
  assert.equal(saved.geoIpDir, "/cases/geoip");
  assert.equal(saved.outputMode, "jsonl");
  assert.equal(saved.profile, "super-verbose");
  assert.equal(saved.rulesPath, "/cases/rules");
  assert.equal(saved.rulesConfig, "/cases/config/default.yaml");
  assert.equal(saved.hayabusaMinSeverity, "high");
  assert.deepEqual(settingsStore.loadDetectionSettings(), saved);
});

test("detection settings expose persisted path authorization entries", (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-detection-paths-"));
  const previousUserData = process.env.TLE_USER_DATA_PATH;
  const settingsStore = loadSettingsModule(userDataPath);

  t.after(() => {
    if (previousUserData === undefined) delete process.env.TLE_USER_DATA_PATH;
    else process.env.TLE_USER_DATA_PATH = previousUserData;
    try { fs.rmSync(userDataPath, { recursive: true, force: true }); } catch {}
  });

  const entries = settingsStore.getDetectionSettingsPathEntries({
    rulesPath: "/cases/rules",
    rulesConfig: "/cases/rules/config/default.yaml",
    geoIpDir: "/cases/geoip",
  });

  assert.deepEqual(entries.map((entry) => entry.key), ["rulesPath", "rulesConfig", "geoIpDir"]);
  assert.deepEqual(entries[0].scopes, ["hayabusa-rules", "compat-rules"]);
  assert.equal(entries[0].recursive, true);
  assert.deepEqual(entries[1].scopes, ["hayabusa-rules-config", "hayabusa-rules"]);
  assert.equal(entries[1].recursive, false);
  assert.deepEqual(entries[2].scopes, ["geoip"]);
  assert.equal(entries[2].recursive, true);
});
