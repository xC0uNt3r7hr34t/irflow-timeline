"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const {
  assertValidSessionPayload,
  writeSessionAtomic,
  readSessionWithBackup,
} = require("../electron/utils/session-persistence");

function session(savedAt, name = "Evidence") {
  return {
    version: 1,
    savedAt,
    activeTabIndex: 0,
    tabs: [{
      filePath: "/evidence/timeline.csv",
      name,
      bookmarkedRowIds: [4, 9],
      tags: { 4: ["review"] },
    }],
  };
}

test("atomic session writes rotate the previous valid snapshot to backup", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-atomic-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const backup = `${primary}.bak`;
  const first = session("2026-08-11T00:00:00.000Z", "First");
  const second = session("2026-08-11T00:01:00.000Z", "Second");

  await writeSessionAtomic(primary, first, { backupPath: backup });
  await writeSessionAtomic(primary, second, { backupPath: backup });

  assert.deepEqual(JSON.parse(await fsp.readFile(primary, "utf8")), second);
  assert.deepEqual(JSON.parse(await fsp.readFile(backup, "utf8")), first);
  assert.deepEqual(fs.readdirSync(tmp).sort(), ["autosave.tle", "autosave.tle.bak"]);
});

test("autosave recovery falls back to the last valid backup", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-recovery-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const backup = `${primary}.bak`;
  const first = session("2026-08-11T00:00:00.000Z", "Recover Me");
  const second = session("2026-08-11T00:01:00.000Z", "Corrupt Me");

  await writeSessionAtomic(primary, first, { backupPath: backup });
  await writeSessionAtomic(primary, second, { backupPath: backup });
  await fsp.writeFile(primary, '{"version":1,"tabs":[', "utf8");

  const loaded = await readSessionWithBackup(primary, backup);
  assert.equal(loaded.recoveredFromBackup, true);
  assert.equal(loaded.sourcePath, backup);
  assert.deepEqual(loaded.session, first);
});

test("session validation rejects malformed recovery data before it is written", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-invalid-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const good = session("2026-08-11T00:00:00.000Z");

  await writeSessionAtomic(primary, good);
  await assert.rejects(
    writeSessionAtomic(primary, { version: 1, savedAt: "invalid", activeTabIndex: 0, tabs: [] }),
    /invalid savedAt timestamp/,
  );
  assert.deepEqual(JSON.parse(await fsp.readFile(primary, "utf8")), good);
  assert.throws(() => assertValidSessionPayload({ version: 1 }), /tabs array/);
});

/**
 * Patch the shared fs/promises singleton the module under test holds a reference to.
 * These behaviours belong to the destination filesystem — an attached exFAT drive, an SMB
 * share, a volume being scanned by antivirus — and cannot be provoked from a temp dir.
 */
function patchFsp(overrides) {
  const originals = {};
  for (const [name, make] of Object.entries(overrides)) {
    originals[name] = fsp[name];
    fsp[name] = make(originals[name]);
  }
  return () => { for (const [name, fn] of Object.entries(originals)) fsp[name] = fn; };
}

test("a session still saves when the destination filesystem refuses fsync", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-nofsync-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const target = path.join(tmp, "case.tle");
  const payload = session("2026-09-09T00:00:00.000Z", "On A USB Drive");

  // exFAT/SD-card and SMB/NFS targets can reject fsync outright. The bytes are already
  // written by then, so this must cost durability, not the save.
  const restore = patchFsp({
    open: (realOpen) => async (...args) => {
      const handle = await realOpen(...args);
      handle.sync = async () => { throw Object.assign(new Error("EINVAL: invalid argument, fsync"), { code: "EINVAL" }); };
      return handle;
    },
  });
  let result;
  try {
    result = await writeSessionAtomic(target, payload, { pretty: true });
  } finally { restore(); }

  assert.equal(result.flushed, false, "the write should report that it could not flush");
  assert.equal(result.bytes > 0, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(target, "utf8")), payload);
});

test("a session save survives a transient lock on the new file", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-locked-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const target = path.join(tmp, "case.tle");
  const payload = session("2026-09-09T00:00:00.000Z");

  // Antivirus holding a just-created file is the usual cause on Windows, and it clears.
  let attempts = 0;
  const restore = patchFsp({
    rename: (realRename) => async (from, to) => {
      if (to === target && ++attempts < 3) {
        throw Object.assign(new Error("EPERM: operation not permitted, rename"), { code: "EPERM" });
      }
      return realRename(from, to);
    },
  });
  try {
    await writeSessionAtomic(target, payload, { pretty: true });
  } finally { restore(); }

  assert.equal(attempts, 3, "the rename should have been retried");
  assert.deepEqual(JSON.parse(fs.readFileSync(target, "utf8")), payload);
});

test("a destination that refuses the temp-and-rename dance still gets written", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-norename-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const target = path.join(tmp, "case.tle");
  const payload = session("2026-09-09T00:00:00.000Z", "On A Mounted Image");

  // Mounted images and volumes behind a filter driver can refuse the rename outright.
  // Atomicity is a technique, not the goal — the save must still land.
  const restore = patchFsp({
    rename: () => async () => { throw Object.assign(new Error("EPERM: operation not permitted, rename"), { code: "EPERM" }); },
  });
  let result;
  try {
    result = await writeSessionAtomic(target, payload, { pretty: true });
  } finally { restore(); }

  assert.equal(result.strategy, "in-place");
  assert.deepEqual(JSON.parse(fs.readFileSync(target, "utf8")), payload);
  assert.deepEqual(fs.readdirSync(tmp), ["case.tle"], "no temp file should be left behind");
});

test("a destination that refuses both write strategies reports the original failure", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-stuck-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const target = path.join(tmp, "case.tle");

  const restore = patchFsp({
    rename: () => async () => { throw Object.assign(new Error("EBUSY: resource busy"), { code: "EBUSY" }); },
    open: (realOpen) => async (p, flags, ...rest) => {
      if (flags === "w") throw Object.assign(new Error("EACCES: permission denied, open"), { code: "EACCES" });
      return realOpen(p, flags, ...rest);
    },
  });
  try {
    await assert.rejects(
      writeSessionAtomic(target, session("2026-09-09T00:00:00.000Z"), { pretty: true }),
      /EBUSY/,
    );
  } finally { restore(); }

  assert.equal(fs.existsSync(target), false);
  assert.deepEqual(fs.readdirSync(tmp), [], "the temp file must not be left behind");
});

test("a filesystem that reports a write without producing the file is caught", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-phantom-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const target = path.join(tmp, "case.tle");

  // "Saved" must never be returned for a file that is not on disk. Both the rename and
  // the in-place fallback are made to claim success without writing anything.
  const restore = patchFsp({
    rename: () => async () => {},
    open: (realOpen) => async (p, flags, ...rest) => {
      if (flags === "w") return { writeFile: async () => {}, sync: async () => {}, close: async () => {} };
      return realOpen(p, flags, ...rest);
    },
  });
  try {
    await assert.rejects(
      writeSessionAtomic(target, session("2026-09-09T00:00:00.000Z"), { pretty: true }),
      /could not be read back/,
    );
  } finally { restore(); }
});

test("a truncated write is reported rather than passed off as a saved session", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-short-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const target = path.join(tmp, "case.tle");

  const restore = patchFsp({
    rename: (realRename) => async (from, to) => {
      await realRename(from, to);
      await fsp.truncate(to, 10); // a full volume that accepted only part of the write
    },
  });
  try {
    await assert.rejects(
      writeSessionAtomic(target, session("2026-09-09T00:00:00.000Z"), { pretty: true }),
      /could not be read back/,
    );
  } finally { restore(); }
});

test("a stale size reported straight after the write is not mistaken for a failure", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-stale-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const target = path.join(tmp, "case.tle");
  const payload = session("2026-09-09T00:00:00.000Z", "Stale Metadata");

  // A volume that refused the flush can still report stale metadata for the new file.
  // Verification reads the content back precisely so that cannot fail a good save.
  const restore = patchFsp({
    stat: () => async () => ({ size: 0 }),
    open: (realOpen) => async (...args) => {
      const handle = await realOpen(...args);
      handle.sync = async () => { throw Object.assign(new Error("EINVAL"), { code: "EINVAL" }); };
      return handle;
    },
  });
  let result;
  try {
    result = await writeSessionAtomic(target, payload, { pretty: true });
  } finally { restore(); }

  assert.equal(result.flushed, false);
  assert.deepEqual(JSON.parse(fs.readFileSync(target, "utf8")), payload);
});

test("session recovery reports corruption when neither snapshot is valid", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-both-corrupt-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const backup = `${primary}.bak`;
  await fsp.writeFile(primary, "not-json", "utf8");
  await fsp.writeFile(backup, JSON.stringify({ version: 1, tabs: [] }), "utf8");

  await assert.rejects(readSessionWithBackup(primary, backup), /No valid session snapshot/);
});
