/**
 * logger.js — Shared debug trace logger for IRFlow Timeline (Windows build)
 *
 * Windows-specific changes from macOS original:
 *  - Log file location changed from os.homedir() ("C:\Users\<name>\tle-debug.log")
 *    to app.getPath("userData") so it lands inside AppData\Roaming\IRFlow Timeline\
 *    alongside the other app data files, following Windows conventions.
 *  - Because app may not be ready yet when this module first loads (it is required
 *    at the top of main.js before app.whenReady()), we fall back to os.homedir()
 *    if the Electron app object is not yet available, then switch to userData on
 *    first write after the app is ready.  In practice, the Electron app object is
 *    accessible synchronously from the main process even before whenReady(), so
 *    app.getPath("userData") works fine here.
 *  - All other logic is unchanged — the flush timer and exit hook are platform-agnostic.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");

// Resolve log path: prefer Electron userData (AppData\Roaming\...) on Windows,
// fall back to home directory if Electron is not available (e.g. unit tests).
function _resolveLogPath() {
  try {
    const { app } = require("electron");
    // app.getPath("userData") is synchronously available in the main process
    // even before app.whenReady() resolves.
    const userData = app.getPath("userData");
    // Ensure the directory exists (it usually does, but may not on first run)
    if (!fs.existsSync(userData)) fs.mkdirSync(userData, { recursive: true });
    return path.join(userData, "tle-debug.log");
  } catch {
    // Fallback for non-Electron contexts (tests, CLI tools)
    return path.join(os.homedir(), "tle-debug.log");
  }
}

const debugLogPath = _resolveLogPath();

// Rotate on startup: truncate if >5 MB to prevent unbounded growth
try {
  if (fs.existsSync(debugLogPath) && fs.statSync(debugLogPath).size > 5 * 1024 * 1024) {
    fs.writeFileSync(debugLogPath, "");
  }
} catch {}

let _logBuf = [];
let _flushPending = false;

function dbg(tag, msg, data) {
  const ts = new Date().toISOString();
  const line = `[${ts}] [${tag}] ${msg}${data !== undefined ? " " + JSON.stringify(data, null, 0) : ""}`;
  console.error(line);
  _logBuf.push(line);
  if (_logBuf.length >= 50) _flushLog();
}

function _flushLog() {
  if (!_logBuf.length || _flushPending) return;
  _flushPending = true;
  const chunk = _logBuf.join("\n") + "\n";
  _logBuf = [];
  fs.appendFile(debugLogPath, chunk, () => { _flushPending = false; });
}

function _flushLogSync() {
  if (!_logBuf.length) return;
  try { fs.appendFileSync(debugLogPath, _logBuf.join("\n") + "\n"); } catch {}
  _logBuf = [];
}

setInterval(_flushLog, 2000);
process.on("exit", _flushLogSync);

module.exports = { dbg, debugLogPath };
