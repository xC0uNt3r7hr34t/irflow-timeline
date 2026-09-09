// Manual session save (File ▸ Save Session).
//
// safeHandle resolves rather than rejects when a handler throws, so every failure on this
// path is a value the renderer has to inspect. When the handler returned a bare path and
// the caller discarded it, a refused write was indistinguishable from a successful one:
// the examiner picked a location, no .tle appeared, and nothing said why. These tests pin
// the contract that each outcome is reported, and that the chosen path is absolute and
// carries the extension the loader matches on.

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Module = require("node:module");

const HANDLERS_PATH = require.resolve("../electron/ipc/session-handlers");

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** Load the handler module with `electron` stubbed so the save dialog can be driven. */
function loadHandlers({ saveResult, userData }) {
  const calls = { showSaveDialog: [] };
  const origLoad = Module._load;
  Module._load = function (request) {
    if (request === "electron") {
      return {
        app: { getPath: () => userData },
        shell: { openPath: async () => "" },
        dialog: {
          showSaveDialog: async (_win, options) => {
            calls.showSaveDialog.push(options);
            return typeof saveResult === "function" ? saveResult(options) : saveResult;
          },
        },
      };
    }
    return origLoad.apply(this, arguments);
  };
  delete require.cache[HANDLERS_PATH];
  let register;
  try { register = require(HANDLERS_PATH); } finally { Module._load = origLoad; }

  const channels = {};
  register((ch, fn) => { channels[ch] = fn; }, () => {}, {
    db: {},
    _activeWindow: () => null,
    enqueueImport: () => {},
    _loadRecentFiles: () => [],
    _saveRecentFiles: () => {},
    _rebuildMenu: () => {},
    _tabMeta: new Map(),
    _pendingIndexTabs: [],
    nextTabId: () => "tab_1",
    updateController: {},
    jobManager: {},
    scheduleIndexBuild: () => {},
  });
  return { channels, calls };
}

function sessionPayload(over = {}) {
  return {
    version: 1,
    savedAt: "2026-09-09T13:00:00.000Z",
    activeTabIndex: 0,
    tabs: [{
      filePath: "C:\\Cases\\Security.csv",
      name: "Security.csv",
      bookmarkedRowIds: [4, 9],
      tags: { 4: ["lateral"] },
    }],
    ...over,
  };
}

test("save-session creates the file for a session that has never been saved", async () => {
  const dir = tmpdir("tle-save-ok-");
  const target = path.join(dir, "case.tle");
  assert.equal(fs.existsSync(target), false, "precondition: this session has no file yet");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target }, userData: dir });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.error, undefined);
  assert.equal(result.path, target);
  assert.equal(result.tabCount, 1);
  assert.ok(result.bytes > 0);
  assert.equal(fs.existsSync(target), true, "the .tle file should exist on disk");

  const written = JSON.parse(fs.readFileSync(target, "utf8"));
  assert.equal(written.version, 1);
  assert.deepEqual(written.tabs[0].bookmarkedRowIds, [4, 9]);
});

test("save-session creates a first save into a directory that does not exist yet", async () => {
  const dir = tmpdir("tle-save-newdir-");
  // writeSessionAtomic mkdirs recursively; the temp file and the rename both have to land
  // in a directory it just created, which only happens on a genuine first save.
  const target = path.join(dir, "Case 2026-09", "evidence", "case.tle");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target }, userData: dir });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.error, undefined);
  assert.equal(fs.existsSync(target), true);
  assert.equal(JSON.parse(fs.readFileSync(target, "utf8")).version, 1);
});

test("save-session leaves no temp artefact next to a first save", async () => {
  const dir = tmpdir("tle-save-clean-");
  const target = path.join(dir, "case.tle");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target }, userData: dir });

  await channels["save-session"](null, { sessionData: sessionPayload() });

  // A leftover .tmp beside the session would look like a half-written save to an examiner.
  assert.deepEqual(fs.readdirSync(dir), ["case.tle"]);
});

test("save-session appends .tle when the chosen name lacks it", async () => {
  const dir = tmpdir("tle-save-ext-");
  const { channels } = loadHandlers({
    saveResult: { canceled: false, filePath: path.join(dir, "case-notes") },
    userData: dir,
  });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  // Without the extension the file cannot be reopened — isTleSessionPath gates the loader.
  assert.equal(result.path, path.join(dir, "case-notes.tle"));
  assert.equal(fs.existsSync(result.path), true);
});

test("save-session keeps an extension it already has, whatever the case", async () => {
  const dir = tmpdir("tle-save-case-");
  const { channels } = loadHandlers({
    saveResult: { canceled: false, filePath: path.join(dir, "CASE.TLE") },
    userData: dir,
  });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });
  assert.equal(result.path, path.join(dir, "CASE.TLE"));
});

test("save-session resolves a relative path instead of writing beside the executable", async () => {
  const dir = tmpdir("tle-save-rel-");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: "case.tle" }, userData: dir });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.error, undefined);
  assert.equal(path.isAbsolute(result.path), true, "a relative dialog result must be resolved");
  fs.rmSync(result.path, { force: true });
});

test("save-session offers an absolute, .tle-suffixed default path", async () => {
  const dir = tmpdir("tle-save-default-");
  const { channels, calls } = loadHandlers({ saveResult: { canceled: true }, userData: dir });

  await channels["save-session"](null, { sessionData: sessionPayload() });

  const [options] = calls.showSaveDialog;
  assert.equal(path.isAbsolute(options.defaultPath), true);
  assert.match(options.defaultPath, /\.tle$/);
  // A colon is not a legal filename character on Windows, so the ISO stamp must be cleaned.
  assert.equal(path.basename(options.defaultPath).includes(":"), false);
});

test("save-session reports cancellation distinctly from failure", async () => {
  const dir = tmpdir("tle-save-cancel-");
  const { channels } = loadHandlers({ saveResult: { canceled: true }, userData: dir });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.canceled, true);
  assert.equal(result.error, undefined);
});

test("save-session refuses an invalid payload before prompting for a location", async () => {
  const dir = tmpdir("tle-save-invalid-");
  const { channels, calls } = loadHandlers({
    saveResult: { canceled: false, filePath: path.join(dir, "case.tle") },
    userData: dir,
  });

  // A tab whose filePath never got populated used to fail validation inside the write,
  // i.e. after the examiner had already chosen where to put the file.
  const payload = sessionPayload({
    tabs: [{ name: "Merged Timeline", bookmarkedRowIds: [], tags: {} }],
  });
  const result = await channels["save-session"](null, { sessionData: payload });

  assert.match(result.error, /cannot be saved/i);
  assert.deepEqual(calls.showSaveDialog, [], "the dialog should not open for an unsaveable session");
  assert.equal(fs.existsSync(path.join(dir, "case.tle")), false);
});

test("save-session surfaces a write failure instead of looking like a success", async () => {
  const dir = tmpdir("tle-save-fail-");
  // A directory standing where the file should go makes the atomic write fail the way a
  // permission or full-disk error would.
  const target = path.join(dir, "case.tle");
  fs.mkdirSync(target);
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target }, userData: dir });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.ok(result.error, "a failed write must report an error");
  assert.equal(result.path, target);
  assert.equal(result.bytes, undefined);
});
