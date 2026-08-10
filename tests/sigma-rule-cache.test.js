const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

test("Sigma rule cache uses worker-provided userData path when electron.app is unavailable", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-cache-test-"));
  const previous = process.env.TLE_USER_DATA_PATH;
  process.env.TLE_USER_DATA_PATH = tmpDir;

  try {
    const ruleCachePath = require.resolve("../electron/analyzers/sigma/rule-cache");
    delete require.cache[ruleCachePath];
    const { getCacheDir, getCacheStatus } = require("../electron/analyzers/sigma/rule-cache");

    assert.equal(getCacheDir(), path.join(tmpDir, "sigma-rules"));
    assert.equal(getCacheStatus().cacheDir, path.join(tmpDir, "sigma-rules"));
  } finally {
    if (previous === undefined) delete process.env.TLE_USER_DATA_PATH;
    else process.env.TLE_USER_DATA_PATH = previous;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
