const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  isTleSessionPath,
  isValidSessionPayload,
  loadSessionFromPath,
  sessionPathExists,
} = require("../electron/session-file");

test("isTleSessionPath matches .tle extension case-insensitively", () => {
  assert.equal(isTleSessionPath("/tmp/session.tle"), true);
  assert.equal(isTleSessionPath("C:\\Cases\\session.TLE"), true);
  assert.equal(isTleSessionPath("/tmp/Security.evtx"), false);
});

test("isValidSessionPayload requires version 1 and tabs array", () => {
  assert.equal(isValidSessionPayload({ version: 1, tabs: [] }), true);
  assert.equal(isValidSessionPayload({ version: 2, tabs: [] }), false);
  assert.equal(isValidSessionPayload({ version: 1 }), false);
  assert.equal(isValidSessionPayload(null), false);
});

test("loadSessionFromPath reads a valid session file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-session-"));
  const sessionPath = path.join(dir, "session.tle");
  const payload = {
    version: 1,
    savedAt: "2026-01-01T00:00:00.000Z",
    activeTabIndex: 0,
    tabs: [{ filePath: "/tmp/a.csv", name: "a.csv" }],
  };
  fs.writeFileSync(sessionPath, JSON.stringify(payload), "utf-8");
  const loaded = loadSessionFromPath(sessionPath);
  assert.equal(loaded.version, 1);
  assert.equal(loaded.tabs.length, 1);
  assert.equal(loaded.tabs[0].name, "a.csv");
});

test("loadSessionFromPath returns error for missing files", () => {
  const result = loadSessionFromPath(path.join(os.tmpdir(), "missing-session.tle"));
  assert.ok(result.error);
  assert.match(result.error, /not found/i);
});

test("loadSessionFromPath returns error for invalid JSON session", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-session-bad-"));
  const sessionPath = path.join(dir, "bad.tle");
  fs.writeFileSync(sessionPath, "{ not json", "utf-8");
  const result = loadSessionFromPath(sessionPath);
  assert.ok(result.error);
});

test("sessionPathExists normalizes relative paths", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-session-exists-"));
  const sessionPath = path.join(dir, "session.tle");
  fs.writeFileSync(sessionPath, "{}", "utf-8");
  assert.equal(sessionPathExists(sessionPath), true);
});
