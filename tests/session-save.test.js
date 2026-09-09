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

/**
 * Load the handler module with `electron` stubbed so the save dialog can be driven.
 * `userData` stands in for app.getPath("userData") and must be its own directory — the
 * real one is app-private, so anything the handler keeps there (the remembered session
 * path) must not be mistaken for an artefact of the folder being saved into.
 */
function loadHandlers({ saveResult, userData = tmpdir("tle-userdata-") }) {
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
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target } });

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
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target } });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.error, undefined);
  assert.equal(fs.existsSync(target), true);
  assert.equal(JSON.parse(fs.readFileSync(target, "utf8")).version, 1);
});

test("save-session leaves no temp artefact next to a first save", async () => {
  const dir = tmpdir("tle-save-clean-");
  const target = path.join(dir, "case.tle");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target } });

  await channels["save-session"](null, { sessionData: sessionPayload() });

  // A leftover .tmp beside the session would look like a half-written save to an examiner.
  assert.deepEqual(fs.readdirSync(dir), ["case.tle"]);
});

test("save-session appends .tle when the chosen name lacks it", async () => {
  const dir = tmpdir("tle-save-ext-");
  const { channels } = loadHandlers({
    saveResult: { canceled: false, filePath: path.join(dir, "case-notes") },
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
  });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });
  assert.equal(result.path, path.join(dir, "CASE.TLE"));
});

test("save-session resolves a relative path instead of writing beside the executable", async () => {
  const dir = tmpdir("tle-save-rel-");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: "case.tle" } });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.error, undefined);
  assert.equal(path.isAbsolute(result.path), true, "a relative dialog result must be resolved");
  fs.rmSync(result.path, { force: true });
});

test("save-session offers an absolute, .tle-suffixed default path", async () => {
  const dir = tmpdir("tle-save-default-");
  const { channels, calls } = loadHandlers({ saveResult: { canceled: true } });

  await channels["save-session"](null, { sessionData: sessionPayload() });

  const [options] = calls.showSaveDialog;
  assert.equal(path.isAbsolute(options.defaultPath), true);
  assert.match(options.defaultPath, /\.tle$/);
  // A colon is not a legal filename character on Windows, so the ISO stamp must be cleaned.
  assert.equal(path.basename(options.defaultPath).includes(":"), false);
});

test("save-session reports cancellation distinctly from failure", async () => {
  const dir = tmpdir("tle-save-cancel-");
  const { channels } = loadHandlers({ saveResult: { canceled: true } });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.canceled, true);
  assert.equal(result.error, undefined);
});

test("save-session refuses an invalid payload before prompting for a location", async () => {
  const dir = tmpdir("tle-save-invalid-");
  const { channels, calls } = loadHandlers({
    saveResult: { canceled: false, filePath: path.join(dir, "case.tle") },
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

test("save-session replaces an existing file that was picked in the dialog", async () => {
  const dir = tmpdir("tle-save-over-");
  const target = path.join(dir, "case.tle");
  fs.writeFileSync(target, JSON.stringify(sessionPayload({ activeTabIndex: 7 })), "utf8");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target } });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(result.error, undefined);
  assert.equal(result.replaced, true, "the handler should report that it replaced a file");
  assert.equal(JSON.parse(fs.readFileSync(target, "utf8")).activeTabIndex, 0, "content should be the new session");
  assert.deepEqual(fs.readdirSync(dir), ["case.tle"]);
});

test("save-session asks for overwrite confirmation only where it is documented", async () => {
  const { channels, calls } = loadHandlers({ saveResult: { canceled: true } });

  await channels["save-session"](null, { sessionData: sessionPayload() });

  const { properties } = calls.showSaveDialog[0];
  if (process.platform === "win32") {
    // Windows prompts natively and documents neither property; passing options a platform
    // does not recognise to a native dialog is not worth the risk.
    assert.equal(properties, undefined);
  } else {
    assert.ok(properties.includes("showOverwriteConfirmation"));
  }
});

test("save-session defaults to the file it last wrote, so re-saving overwrites it", async () => {
  const dir = tmpdir("tle-save-remember-");
  const userData = tmpdir("tle-save-remember-ud-"); // shared, as one install would be
  const target = path.join(dir, "operation-badger.tle");
  const first = loadHandlers({ saveResult: { canceled: false, filePath: target }, userData });
  await first.channels["save-session"](null, { sessionData: sessionPayload() });

  const second = loadHandlers({ saveResult: { canceled: true }, userData });
  await second.channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(second.calls.showSaveDialog[0].defaultPath, target);
});

test("save-session defaults to the session that was opened", async () => {
  const dir = tmpdir("tle-save-after-open-");
  const opened = path.join(dir, "from-disk.tle");
  fs.writeFileSync(opened, JSON.stringify(sessionPayload()), "utf8");
  const { channels, calls } = loadHandlers({ saveResult: { canceled: true } });

  const loaded = await channels["load-session-from-path"](null, { filePath: opened });
  assert.equal(loaded.error, undefined);
  await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.equal(calls.showSaveDialog[0].defaultPath, opened);
});

test("save-session ignores a remembered path whose folder has gone away", async () => {
  const dir = tmpdir("tle-save-stale-");
  const userData = tmpdir("tle-save-stale-ud-");
  const gone = path.join(dir, "unmounted-case");
  fs.mkdirSync(gone);
  const target = path.join(gone, "case.tle");
  const first = loadHandlers({ saveResult: { canceled: false, filePath: target }, userData });
  await first.channels["save-session"](null, { sessionData: sessionPayload() });

  fs.rmSync(gone, { recursive: true, force: true });

  const second = loadHandlers({ saveResult: { canceled: true }, userData });
  await second.channels["save-session"](null, { sessionData: sessionPayload() });

  const { defaultPath } = second.calls.showSaveDialog[0];
  assert.notEqual(defaultPath, target);
  assert.match(defaultPath, /\.tle$/);
});

test("save-session surfaces a write failure instead of looking like a success", async () => {
  const dir = tmpdir("tle-save-fail-");
  // A directory standing where the file should go makes the atomic write fail the way a
  // permission or full-disk error would.
  const target = path.join(dir, "case.tle");
  fs.mkdirSync(target);
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target } });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.ok(result.error, "a failed write must report an error");
  assert.equal(result.path, target);
  assert.equal(result.bytes, undefined);
  // The atomic write works through a temp file; naming it in the error reads like a bug
  // report rather than something the examiner can act on.
  assert.doesNotMatch(result.error, /\.tmp/);
});

test("save-session explains a permission failure in the examiner's terms", async (t) => {
  const dir = tmpdir("tle-save-perm-");
  const readOnly = path.join(dir, "read-only");
  fs.mkdirSync(readOnly, 0o500);
  if (process.getuid && process.getuid() === 0) {
    t.skip("running as root — directory permissions are not enforced");
    return;
  }
  const target = path.join(readOnly, "case.tle");
  const { channels } = loadHandlers({ saveResult: { canceled: false, filePath: target } });

  const result = await channels["save-session"](null, { sessionData: sessionPayload() });

  assert.match(result.error, /permission denied/i);
  assert.ok(result.error.includes(readOnly), "the message should name the folder that refused the write");
  assert.doesNotMatch(result.error, /\.tmp/);
});
