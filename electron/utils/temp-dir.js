/**
 * temp-dir.js — Resolves where per-tab temp SQLite databases (+ their column/FTS indexes
 * and SQLite spill files) are written.
 *
 * Large imports build a database that can total a few times the source size. By default
 * this lives on the OS temp volume (usually the boot disk). An analyst working 30-50GB
 * files can redirect it to a scratch/external volume so the boot disk isn't filled.
 *
 * Resolution precedence:
 *   1. User-chosen folder (persisted via the "Set Temp Storage Folder…" menu item)
 *   2. TLE_TEMP_DIR environment variable (for headless/admin/power-user setups)
 *   3. os.tmpdir() (default)
 * A candidate is only used if it exists and is writable; otherwise we fall through.
 *
 * Main-process only (requires electron `app` for userData). Used by main.js (_newTempDbPath),
 * import.js (the free-disk pre-check) and menu.js (the picker).
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { app } = require("electron");

function _configPath() {
  try { return path.join(app.getPath("userData"), "temp-storage.json"); } catch { return null; }
}

function loadTempDirSetting() {
  const p = _configPath();
  if (!p) return null;
  try {
    const d = JSON.parse(fs.readFileSync(p, "utf8"));
    return typeof d.dir === "string" && d.dir ? d.dir : null;
  } catch { return null; }
}

function saveTempDirSetting(dir) {
  const p = _configPath();
  if (!p) return;
  try {
    if (dir) fs.writeFileSync(p, JSON.stringify({ dir }), "utf8");
    else { try { fs.unlinkSync(p); } catch {} }
  } catch {}
}

function isUsable(dir) {
  if (!dir || typeof dir !== "string") return false;
  try {
    if (!fs.statSync(dir).isDirectory()) return false;
    fs.accessSync(dir, fs.constants.W_OK);
    return true;
  } catch { return false; }
}

function resolveTempDir() {
  const setting = loadTempDirSetting();
  if (isUsable(setting)) return setting;
  const env = process.env.TLE_TEMP_DIR;
  if (isUsable(env)) return env;
  return os.tmpdir();
}

module.exports = { resolveTempDir, loadTempDirSetting, saveTempDirSetting, isUsable };
