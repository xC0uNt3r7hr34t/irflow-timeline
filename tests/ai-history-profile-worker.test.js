"use strict";

// Guard for the temp-DB leak: the worker now unlinks its scratch SQLite (+ WAL/SHM) on the
// cancel/error/empty paths. The worker module is require-safe on the main thread (it only runs
// its extract when loaded as a real worker), so we can unit-test the cleanup helper directly.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { unlinkTempDb } = require("../electron/jobs/ai-history-profile-worker");

test("unlinkTempDb removes the temp DB plus its WAL/SHM siblings", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-"));
  const dbPath = path.join(dir, "tle_tab.db");
  try {
    for (const suffix of ["", "-wal", "-shm"]) fs.writeFileSync(`${dbPath}${suffix}`, "x");
    unlinkTempDb(dbPath);
    for (const suffix of ["", "-wal", "-shm"]) {
      assert.equal(fs.existsSync(`${dbPath}${suffix}`), false, `${suffix || "db"} should be removed`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("unlinkTempDb tolerates missing files and falsy paths", () => {
  assert.doesNotThrow(() => unlinkTempDb(path.join(os.tmpdir(), "irflow-nope-does-not-exist.db")));
  assert.doesNotThrow(() => unlinkTempDb(""));
  assert.doesNotThrow(() => unlinkTempDb(null));
});
