// Unit tests for the renderer IPC-result helpers (src/utils/ipc-result.js).
// The ESM module is loaded via the strip-export + vm sandbox pattern used elsewhere.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadModule() {
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "utils", "ipc-result.js"), "utf8");
  const munged = src.replace(/^export\s+function\s+/gm, "function ");
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(munged + "\n;Object.assign(globalThis,{isIpcError,ipcErrorMessage,isIpcCancelled});", ctx);
  return { isIpcError: ctx.isIpcError, ipcErrorMessage: ctx.ipcErrorMessage, isIpcCancelled: ctx.isIpcCancelled };
}
const { isIpcError, ipcErrorMessage, isIpcCancelled } = loadModule();

test("isIpcError detects __ipcError (worker crash) and non-empty error strings", () => {
  assert.equal(isIpcError({ __ipcError: true }), true);
  assert.equal(isIpcError({ __ipcError: true, message: "boom" }), true);
  assert.equal(isIpcError({ error: "No database" }), true);
});

test("isIpcError treats success results / empty errors as not-an-error", () => {
  assert.equal(isIpcError({ error: "" }), false);
  assert.equal(isIpcError({ counts: {}, data: [1, 2] }), false);
  assert.equal(isIpcError({}), false);
  assert.equal(isIpcError(null), false);
  assert.equal(isIpcError(undefined), false);
  assert.equal(isIpcError("nope"), false);
  assert.equal(isIpcError([]), false);
});

test("ipcErrorMessage prefers message, then error, then fallback", () => {
  assert.equal(ipcErrorMessage({ __ipcError: true, message: "worker crashed" }), "worker crashed");
  assert.equal(ipcErrorMessage({ error: "No database" }), "No database");
  assert.equal(ipcErrorMessage({ message: "m", error: "e" }), "m");
  assert.equal(ipcErrorMessage({ __ipcError: true }), "Analysis failed");
  assert.equal(ipcErrorMessage({ __ipcError: true }, "custom fallback"), "custom fallback");
  assert.equal(ipcErrorMessage(null), "Analysis failed");
});

test("isIpcCancelled detects safeHandle cancellation errors", () => {
  assert.equal(isIpcCancelled({ __ipcError: true, message: "Job cancelled" }), true);
  assert.equal(isIpcCancelled({ error: "Query canceled" }), true);
  assert.equal(isIpcCancelled({ __ipcError: true, message: "Worker exited with code 1" }), false);
  assert.equal(isIpcCancelled({ rows: [] }), false);
});
