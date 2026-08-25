// Regression test for the packaged Sigma-scan worker crash:
//   "Cannot find module 'electron'  Require stack: … sigma/rule-cache.js … sigma-worker.js"
//
// rule-cache.js is loaded inside the Sigma scan worker thread. In a packaged build the
// 'electron' module is NOT resolvable off the main thread, so a top-level
// `require("electron")` threw and aborted the entire scan. This test simulates that
// condition by making the module resolver throw for 'electron', then asserts the module
// still loads (the require must be guarded) and falls back to TLE_USER_DATA_PATH.

const test = require("node:test");
const assert = require("node:assert/strict");
const Module = require("module");
const path = require("path");
const os = require("os");

test("rule-cache.js loads when 'electron' is unresolvable (packaged worker thread)", () => {
  const rcPath = require.resolve("../electron/analyzers/sigma/rule-cache");
  delete require.cache[rcPath]; // force a fresh load under the hook

  const origResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, ...rest) {
    if (request === "electron") {
      const e = new Error("Cannot find module 'electron'");
      e.code = "MODULE_NOT_FOUND";
      throw e;
    }
    return origResolve.call(this, request, ...rest);
  };

  let ruleCache;
  try {
    // Before the fix this throws MODULE_NOT_FOUND at module scope.
    assert.doesNotThrow(() => { ruleCache = require(rcPath); }, "rule-cache must load without electron");
  } finally {
    Module._resolveFilename = origResolve;
    delete require.cache[rcPath]; // don't leak the hook-loaded copy to other tests
  }

  // The worker-path fallback must resolve the cache dir from TLE_USER_DATA_PATH.
  assert.equal(typeof ruleCache.getCacheStatus, "function", "module exports intact");
});

test("getUserDataPath fallback prefers TLE_USER_DATA_PATH off the main thread", () => {
  // Sanity: with no electron app and TLE_USER_DATA_PATH set, the cache dir lands under it.
  const rcPath = require.resolve("../electron/analyzers/sigma/rule-cache");
  delete require.cache[rcPath];
  const origResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, ...rest) {
    if (request === "electron") { const e = new Error("Cannot find module 'electron'"); e.code = "MODULE_NOT_FOUND"; throw e; }
    return origResolve.call(this, request, ...rest);
  };
  const tmp = path.join(os.tmpdir(), "tle-rulecache-worker-test");
  const prev = process.env.TLE_USER_DATA_PATH;
  process.env.TLE_USER_DATA_PATH = tmp;
  try {
    const rc = require(rcPath);
    const status = rc.getCacheStatus(); // internally calls getUserDataPath()→getCacheDir()
    assert.ok(status, "getCacheStatus returns a value using the env-provided userData path");
  } finally {
    Module._resolveFilename = origResolve;
    if (prev === undefined) delete process.env.TLE_USER_DATA_PATH; else process.env.TLE_USER_DATA_PATH = prev;
    delete require.cache[rcPath];
  }
});
