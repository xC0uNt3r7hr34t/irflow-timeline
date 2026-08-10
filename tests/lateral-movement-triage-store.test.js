const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

function loadStore(userDataPath) {
  process.env.TLE_USER_DATA_PATH = userDataPath;
  const modulePath = require.resolve("../electron/analyzers/lateral-movement/triage-store");
  delete require.cache[modulePath];
  return require("../electron/analyzers/lateral-movement/triage-store");
}

test("lateral movement triage store persists marks by analysis scope", (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "tle-lm-triage-"));
  t.after(() => {
    delete process.env.TLE_USER_DATA_PATH;
    fs.rmSync(userDataPath, { recursive: true, force: true });
  });
  const store = loadStore(userDataPath);
  const scopeA = { id: "scope-a", label: "Case A", tabIds: ["tab-a"] };
  const scopeB = { id: "scope-b", label: "Case B", tabIds: ["tab-b"] };

  const saved = store.saveLateralMovementTriage(scopeA, {
    reviewed: { finding1: "2026-05-01T00:00:00.000Z" },
    falsePositive: { finding2: "2026-05-01T00:01:00.000Z" },
  });

  assert.ok(fs.existsSync(store.getTriageFile()));
  assert.equal(saved.reviewed.finding1, "2026-05-01T00:00:00.000Z");
  assert.equal(saved.falsePositive.finding2, "2026-05-01T00:01:00.000Z");

  const loadedA = store.loadLateralMovementTriage(scopeA);
  const loadedB = store.loadLateralMovementTriage(scopeB);
  assert.deepEqual(Object.keys(loadedA.reviewed), ["finding1"]);
  assert.deepEqual(Object.keys(loadedA.falsePositive), ["finding2"]);
  assert.deepEqual(loadedB.reviewed, {});
  assert.deepEqual(loadedB.falsePositive, {});
});

test("lateral movement triage store clears one scope without deleting others", (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "tle-lm-triage-clear-"));
  t.after(() => {
    delete process.env.TLE_USER_DATA_PATH;
    fs.rmSync(userDataPath, { recursive: true, force: true });
  });
  const store = loadStore(userDataPath);

  store.saveLateralMovementTriage({ id: "scope-a" }, { reviewed: { a: "now" } });
  store.saveLateralMovementTriage({ id: "scope-b" }, { falsePositive: { b: "now" } });
  store.clearLateralMovementTriage({ id: "scope-a" });

  assert.deepEqual(store.loadLateralMovementTriage({ id: "scope-a" }).reviewed, {});
  assert.deepEqual(Object.keys(store.loadLateralMovementTriage({ id: "scope-b" }).falsePositive), ["b"]);
});
