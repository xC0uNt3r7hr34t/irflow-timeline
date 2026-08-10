/**
 * Worker-thread V8 heap limits.
 *
 * Worker threads do NOT inherit `v8.setFlagsFromString` / `app.commandLine.appendSwitch`
 * from main.js — they default to a much smaller old-space cap and can hit
 * FATAL ERROR: Reached heap limit during large AI-history / import jobs.
 */

const DEFAULT_WORKER_HEAP_MB = 8192;

function workerHeapMb() {
  const raw = process.env.TLE_WORKER_HEAP_MB;
  if (raw != null && raw !== "") {
    const n = Number(raw);
    if (Number.isFinite(n) && n > 0) return Math.floor(n);
  }
  return DEFAULT_WORKER_HEAP_MB;
}

function workerResourceLimits() {
  return {
    maxOldGenerationSizeMb: workerHeapMb(),
  };
}

module.exports = { workerResourceLimits, workerHeapMb, DEFAULT_WORKER_HEAP_MB };
