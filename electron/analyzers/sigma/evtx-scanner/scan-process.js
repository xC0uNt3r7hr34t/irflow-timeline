/**
 * sigma/evtx-scanner/scan-process.js — Hayabusa subprocess lifecycle + cancellation.
 *
 * This module deliberately depends only on Node core + the (pure) progress parser
 * — NOT on the SQLite result store or Electron — so the spawn/cancel/crash paths
 * can be unit-tested under plain `node --test` with a fake binary.
 *
 * The single source of truth for "is this scan cancelled" lives here in
 * `_activeProcs`; scan-runner.js re-exports these symbols for compatibility.
 */

const fs = require("fs");
const { spawn } = require("child_process");
const { stripAnsi } = require("./progress-parser");

const _activeProcs = new Map();

function registerScanProc(scanJobId, proc, tempFiles) {
  if (!scanJobId) return;
  const existing = _activeProcs.get(scanJobId);
  const cancelled = !!existing?.cancelled;
  _activeProcs.set(scanJobId, { proc, tempFiles: tempFiles || [], cancelled });
  // If a cancel request raced ahead of the spawn, honour it immediately.
  if (cancelled && proc) {
    try { proc.kill("SIGTERM"); } catch {}
  }
}

function unregisterScanProc(scanJobId) {
  if (!scanJobId) return;
  _activeProcs.delete(scanJobId);
}

function isCancelled(scanJobId) {
  return !!(scanJobId && _activeProcs.get(scanJobId)?.cancelled);
}

function throwIfCancelled(scanJobId) {
  if (isCancelled(scanJobId)) {
    throw Object.assign(new Error("Scan cancelled"), { cancelled: true });
  }
}

function cancelScan(scanJobId) {
  const entry = _activeProcs.get(scanJobId);
  if (!entry) return { cancelled: false, reason: "unknown jobId" };
  entry.cancelled = true;
  try { entry.proc?.kill("SIGTERM"); } catch {}
  setTimeout(() => {
    try {
      if (entry.proc && !entry.proc.killed) entry.proc.kill("SIGKILL");
    } catch {}
  }, 2000);
  for (const file of entry.tempFiles || []) {
    try {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    } catch {}
  }
  return { cancelled: true };
}

/**
 * Spawn Hayabusa and resolve once it exits, reporting the lifecycle outcome.
 *
 * Resolves:
 *   { cancelled: true }                                    — scan was cancelled
 *   { cancelled: false, exitCode, signal, errorLines }     — process finished
 *
 * Rejects only when the process fails to start, or exits non-zero AND produced
 * no output file at all (a hard failure). A non-zero exit that still left an
 * output file resolves with the exit code so the caller can flag the results as
 * partial/truncated rather than silently treating them as complete.
 *
 * @param {object} p
 * @param {string} p.hayabusaPath      path to the hayabusa binary
 * @param {string[]} p.args            CLI args
 * @param {string} p.cwd               working directory for the process
 * @param {string|null} p.scanJobId    cancellation key (registered in _activeProcs)
 * @param {object} p.progressParser    { handleChunk, startTicker, getStderr }
 * @param {string[]} p.tempFiles       files to clean up if cancelled
 * @param {string|null} p.actualOutput output path used to distinguish hard failure
 */
function runScanProcess({ hayabusaPath, args, cwd, scanJobId, progressParser, tempFiles, actualOutput }) {
  return new Promise((resolve, reject) => {
    const proc = spawn(hayabusaPath, args, {
      cwd,
      stdio: ["ignore", "ignore", "pipe"],
    });

    if (scanJobId) registerScanProc(scanJobId, proc, tempFiles || []);

    if (proc.stderr && progressParser?.handleChunk) {
      proc.stderr.on("data", progressParser.handleChunk);
    }
    const ticker = progressParser?.startTicker ? progressParser.startTicker() : null;

    proc.on("close", (code, signal) => {
      if (ticker) clearInterval(ticker);
      if (isCancelled(scanJobId)) {
        resolve({ cancelled: true });
        return;
      }
      const cleanStderr = stripAnsi(progressParser?.getStderr ? progressParser.getStderr() : "");
      const errorLines = cleanStderr
        .split("\n")
        .filter((line) => /\[ERROR\]|error:/i.test(line));
      const outputExists = actualOutput ? fs.existsSync(actualOutput) : false;
      if (code !== 0 && !outputExists) {
        reject(new Error(
          `Hayabusa exited with code ${code}${signal ? ` (signal ${signal})` : ""}: ${errorLines.slice(0, 3).join("; ") || "unknown error"}`
        ));
        return;
      }
      resolve({
        cancelled: false,
        exitCode: code,
        signal: signal || null,
        errorLines: errorLines.slice(0, 5),
      });
    });

    proc.on("error", (err) => {
      if (ticker) clearInterval(ticker);
      if (isCancelled(scanJobId)) {
        resolve({ cancelled: true });
        return;
      }
      reject(new Error(`Failed to start Hayabusa: ${err.message}`));
    });
  });
}

// A non-zero numeric exit OR a signal-kill means the process did not finish
// cleanly — any output it produced may be incomplete/truncated.
function isAbnormalExit(outcome) {
  if (!outcome || outcome.cancelled) return false;
  return (typeof outcome.exitCode === "number" && outcome.exitCode !== 0) || !!outcome.signal;
}

module.exports = {
  _activeProcs,
  registerScanProc,
  unregisterScanProc,
  isCancelled,
  throwIfCancelled,
  cancelScan,
  runScanProcess,
  isAbnormalExit,
};
