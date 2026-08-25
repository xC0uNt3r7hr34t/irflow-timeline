// Regression test for the VirusTotal bulk-lookup crash (release review H2).
//
// Bug: main.js wired the IPC context with a mainWindow proxy whose `isDestroyed` was a
// GETTER returning a boolean:  { get isDestroyed() { return !mainWindow || mainWindow.isDestroyed(); } }
// vt-handlers.js calls it as a METHOD on every loop iteration:
//   if (job.cancelled || (mainWindow && mainWindow.isDestroyed())) break;
// so it invoked a boolean -> "TypeError: <bool> is not a function" on the FIRST iteration,
// before any IOC was looked up. The error was swallowed by the background IIFE's .catch
// (which emits vt-complete with an `error`), and the renderer ignores that error — so
// VirusTotal bulk enrichment silently "finished" with zero results, every time.
//
// Fix: main.js exposes isDestroyed as a method: { isDestroyed() { return !mainWindow || mainWindow.isDestroyed(); } }
//
// Test strategy: drive vt-bulk-lookup with an UNSUPPORTED-category IOC. That path still
// evaluates the mainWindow.isDestroyed() guard (the crash point) but then takes the
// !endpoint branch, so it never hits the network or the better-sqlite3 cache — making
// the regression observable with no native module and no API calls.

const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("os");
const fs = require("fs");
const path = require("path");
const Module = require("node:module");

// vt-handlers.js does `const { app } = require("electron")` and calls
// app.getPath("userData") at module load. Stub `electron` just for that require,
// pointing userData at a temp dir we control, then restore the loader.
const vtTmp = fs.mkdtempSync(path.join(os.tmpdir(), "vt-handlers-test-"));
const electronStub = { app: { getPath: () => vtTmp } };
const origLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === "electron") return electronStub;
  return origLoad.call(this, request, ...rest);
};
let registerVtHandlers;
try {
  registerVtHandlers = require("../electron/ipc/vt-handlers");
} finally {
  Module._load = origLoad;
}

// A configured API key is required or vt-bulk-lookup early-returns { error } before the loop.
fs.writeFileSync(
  path.join(vtTmp, "vt-settings.json"),
  JSON.stringify({ apiKey: "TEST-KEY", rateLimit: 4, cacheTtlHours: 24 })
);

function setupVt(mainWindow) {
  const handlers = {};
  const events = [];
  const safeHandle = (channel, fn) => { handlers[channel] = fn; };
  const safeSend = (channel, payload) => { events.push({ channel, payload }); };
  registerVtHandlers(safeHandle, safeSend, { db: {}, mainWindow });
  return { handlers, events };
}

// Mirrors the post-fix main.js proxy: isDestroyed is a callable method.
const liveWindow = { isDestroyed() { return false; } };
const destroyedWindow = { isDestroyed() { return true; } };

test("vt-bulk-lookup processes IOCs without throwing on the mainWindow.isDestroyed() guard", async () => {
  const { handlers, events } = setupVt(liveWindow);
  const ret = await handlers["vt-bulk-lookup"](null, {
    iocs: [{ raw: "not-a-real-ioc", category: "Unsupported" }],
    requestId: "vt-test-ok",
  });
  assert.deepEqual(ret, { requestId: "vt-test-ok" });

  await new Promise((r) => setTimeout(r, 10)); // let the background IIFE settle

  const complete = events.find((e) => e.channel === "vt-complete" && e.payload.requestId === "vt-test-ok");
  assert.ok(complete, "vt-complete must fire");
  // The regression set complete.payload.error to "... is not a function" with completed:0.
  assert.equal(complete.payload.error, undefined, `bulk loop must not throw (got error: ${complete.payload.error})`);
  assert.equal(complete.payload.completed, 1, "the IOC must be processed (loop ran past the isDestroyed guard)");
  assert.equal(complete.payload.cancelled, false);

  const progress = events.find((e) => e.channel === "vt-progress" && e.payload.requestId === "vt-test-ok");
  assert.ok(progress, "vt-progress must fire for the processed IOC (proves the loop body executed)");
  assert.equal(progress.payload.result.verdict, "unsupported");
});

test("vt-bulk-lookup still honors a destroyed window (isDestroyed() === true stops the loop)", async () => {
  const { handlers, events } = setupVt(destroyedWindow);
  await handlers["vt-bulk-lookup"](null, {
    iocs: [{ raw: "not-a-real-ioc", category: "Unsupported" }],
    requestId: "vt-test-destroyed",
  });

  await new Promise((r) => setTimeout(r, 10));

  const complete = events.find((e) => e.channel === "vt-complete" && e.payload.requestId === "vt-test-destroyed");
  assert.ok(complete, "vt-complete must fire");
  assert.equal(complete.payload.error, undefined);
  assert.equal(complete.payload.completed, 0, "loop must break before processing when the window is destroyed");
  const progress = events.find((e) => e.channel === "vt-progress" && e.payload.requestId === "vt-test-destroyed");
  assert.equal(progress, undefined, "no IOC should be processed when the window is destroyed");
});

test.after(() => { try { fs.rmSync(vtTmp, { recursive: true, force: true }); } catch {} });
