const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const SESSION_VERSION = 1;

function assertValidSessionPayload(session) {
  if (!session || typeof session !== "object" || Array.isArray(session)) {
    throw new Error("Session payload must be an object");
  }
  if (session.version !== SESSION_VERSION) {
    throw new Error(`Unsupported session version: ${session.version ?? "missing"}`);
  }
  if (!Array.isArray(session.tabs)) {
    throw new Error("Session payload is missing its tabs array");
  }
  if (!Number.isInteger(session.activeTabIndex) || session.activeTabIndex < -1) {
    throw new Error("Session payload has an invalid active tab index");
  }
  if (typeof session.savedAt !== "string" || !Number.isFinite(Date.parse(session.savedAt))) {
    throw new Error("Session payload has an invalid savedAt timestamp");
  }
  for (let i = 0; i < session.tabs.length; i++) {
    const tab = session.tabs[i];
    if (!tab || typeof tab !== "object" || Array.isArray(tab)) {
      throw new Error(`Session tab ${i + 1} must be an object`);
    }
    if (typeof tab.filePath !== "string" || typeof tab.name !== "string") {
      throw new Error(`Session tab ${i + 1} is missing its file path or name`);
    }
    if (!Array.isArray(tab.bookmarkedRowIds)) {
      throw new Error(`Session tab ${i + 1} is missing bookmarked row IDs`);
    }
    if (!tab.tags || typeof tab.tags !== "object" || Array.isArray(tab.tags)) {
      throw new Error(`Session tab ${i + 1} is missing tag data`);
    }
  }
  return session;
}

function _tempPathFor(filePath) {
  const token = crypto.randomBytes(8).toString("hex");
  return `${filePath}.${process.pid}.${token}.tmp`;
}

async function _syncDirectory(dirPath) {
  let handle;
  try {
    handle = await fsp.open(dirPath, "r");
    await handle.sync();
  } catch {
    // Directory fsync is not available on every platform/filesystem. The file
    // itself has already been synced, so this is best-effort durability only.
  } finally {
    try { await handle?.close(); } catch {}
  }
}

/**
 * Flush the file, but never fail the write over it.
 *
 * fsync is not available everywhere: it is rejected on some removable media (exFAT, SD
 * cards) and on SMB/NFS shares, which is why saving to an attached drive could fail while
 * the same save to a local profile folder succeeded. The bytes have already been handed to
 * the filesystem by this point, so a refused flush costs durability if the machine loses
 * power — losing the examiner's session instead is far worse.
 */
async function _bestEffortSync(handle) {
  try {
    await handle.sync();
    return true;
  } catch {
    return false;
  }
}

// A newly created file on Windows is routinely held for a moment by antivirus or the
// indexer, and removable volumes are scanned more aggressively than local ones. Those
// locks surface as EPERM/EACCES/EBUSY on the rename and clear on their own.
const RENAME_RETRY_DELAYS_MS = [0, 25, 75, 200];
const TRANSIENT_RENAME_CODES = new Set(["EPERM", "EACCES", "EBUSY", "ETXTBSY"]);

async function _renameWithRetry(from, to) {
  let lastErr;
  for (const delay of RENAME_RETRY_DELAYS_MS) {
    if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
    try {
      await fsp.rename(from, to);
      return;
    } catch (err) {
      lastErr = err;
      if (!TRANSIENT_RENAME_CODES.has(err?.code)) throw err;
    }
  }
  throw lastErr;
}

/**
 * Write through a temp file and rename it into place, so a reader never sees a half
 * written session. Rotates the previous copy to `backupPath` first when one is asked for.
 */
async function _writeViaTempAndRename(filePath, json, backupPath) {
  const tempPath = _tempPathFor(filePath);
  let handle;
  let primaryMovedToBackup = false;
  try {
    handle = await fsp.open(tempPath, "wx", 0o600);
    await handle.writeFile(json, "utf8");
    const flushed = await _bestEffortSync(handle);
    await handle.close();
    handle = null;

    if (backupPath && fs.existsSync(filePath)) {
      await fsp.rm(backupPath, { force: true });
      await fsp.rename(filePath, backupPath);
      primaryMovedToBackup = true;
    }

    try {
      await _renameWithRetry(tempPath, filePath);
    } catch (err) {
      if (primaryMovedToBackup && !fs.existsSync(filePath) && fs.existsSync(backupPath)) {
        try { await fsp.rename(backupPath, filePath); } catch {}
      }
      throw err;
    }
    return flushed;
  } finally {
    try { await handle?.close(); } catch {}
    try { await fsp.rm(tempPath, { force: true }); } catch {}
  }
}

/** Last resort: write the destination in place. Not crash-atomic, but it is a saved file. */
async function _writeInPlace(filePath, json) {
  let handle;
  try {
    handle = await fsp.open(filePath, "w", 0o600);
    await handle.writeFile(json, "utf8");
    return await _bestEffortSync(handle);
  } finally {
    try { await handle?.close(); } catch {}
  }
}

/**
 * Prove the session is on disk and usable by reading it back.
 *
 * Checking the size reported by stat() is not good enough: fsync is best-effort, and on a
 * volume that refused the flush the metadata can still be stale straight after the
 * rename, so a perfectly good save looks truncated. Reading the file goes through the
 * same cache the write went into, and parsing it is a stronger guarantee than a byte
 * count — it also catches a partial write or a filesystem that reported a rename without
 * producing a usable file.
 */
async function _verifyWritten(filePath) {
  const raw = await fsp.readFile(filePath, "utf8");
  assertValidSessionPayload(JSON.parse(raw));
}

async function writeSessionAtomic(filePath, session, { backupPath = null, pretty = false } = {}) {
  assertValidSessionPayload(session);
  const json = JSON.stringify(session, null, pretty ? 2 : 0);
  const expectedBytes = Buffer.byteLength(json, "utf8");
  const dirPath = path.dirname(filePath);

  await fsp.mkdir(dirPath, { recursive: true });

  let flushed = false;
  let strategy = "atomic";
  try {
    flushed = await _writeViaTempAndRename(filePath, json, backupPath);
  } catch (atomicErr) {
    // Creating a sibling temp file and renaming over the target is refused on some
    // destinations — mounted images, restrictive mounts, volumes behind a filter driver.
    // Giving up there would lose the save over a durability technique, so fall back to
    // writing the file directly and report the original, more specific error only if
    // that fails too.
    try {
      flushed = await _writeInPlace(filePath, json);
      strategy = "in-place";
    } catch {
      throw atomicErr;
    }
  }

  await _syncDirectory(dirPath);

  try {
    await _verifyWritten(filePath);
  } catch (err) {
    throw new Error(`The session at ${filePath} could not be read back after writing (${err?.code || err?.message || "unknown error"}).`);
  }

  return { path: filePath, bytes: expectedBytes, flushed, strategy };
}

async function readSessionWithBackup(filePath, backupPath = null) {
  const candidates = [filePath, ...(backupPath ? [backupPath] : [])];
  const failures = [];
  let found = false;

  for (const candidate of candidates) {
    try {
      const raw = await fsp.readFile(candidate, "utf8");
      found = true;
      const session = assertValidSessionPayload(JSON.parse(raw));
      return {
        session,
        sourcePath: candidate,
        recoveredFromBackup: candidate !== filePath,
      };
    } catch (err) {
      if (err?.code === "ENOENT") continue;
      found = true;
      failures.push(`${path.basename(candidate)}: ${err?.message || String(err)}`);
    }
  }

  if (!found) return null;
  throw new Error(`No valid session snapshot was found (${failures.join("; ")})`);
}

module.exports = {
  SESSION_VERSION,
  assertValidSessionPayload,
  writeSessionAtomic,
  readSessionWithBackup,
};
