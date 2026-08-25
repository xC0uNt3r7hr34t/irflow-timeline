const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function strip(src) {
  return src
    .replace(/import\s+[\s\S]*?from\s+["'][^"']+["']\s*;?/g, "")
    .replace(/export\s+(const|function|async function|class|let|var)\s+/g, "$1 ")
    .replace(/export\s*\{[^}]+\}\s*;?/g, "")
    .replace(/export\s+default\s+/g, "");
}

function load() {
  const root = path.join(__dirname, "..");
  const stubs = `
    function openLateralMovementModal(columns, extra) { return { type: "lateralMovement", columns, ...extra }; }
    function openPersistenceModal(extra) { return { type: "persistence", ...extra }; }
    function openSigmaModal(extra) { return { type: "sigma", ...extra }; }
    function buildLateralMovementCols(headers) { return { cols: { ts: "UtcTime", target: "Computer" }, chainsawSyntheticTarget: "" }; }
    function buildPersistenceMode() { return "auto"; }
    function normalizeGuid(v) { return String(v || "").replace(/[{}]/g, "").toLowerCase(); }
  `;
  const normalize = strip(fs.readFileSync(path.join(root, "src/utils/forensic-normalize.js"), "utf8"));
  const identity = strip(fs.readFileSync(path.join(root, "src/utils/process-identity.js"), "utf8"));
  const pivot = strip(fs.readFileSync(path.join(root, "src/utils/process-grid-pivot.js"), "utf8"));
  const handoffs = strip(fs.readFileSync(path.join(root, "src/utils/process-handoffs.js"), "utf8"));
  const sandbox = {
    module: { exports: {} }, exports: {}, console, Math, Date, Number, String, Array, Object, Map, Set, JSON, RegExp,
  };
  vm.createContext(sandbox);
  vm.runInContext(stubs + "\n" + normalize + "\n" + identity + "\n" + pivot + "\n" + handoffs + `
    module.exports = {
      buildProcessHandoff,
      buildProcessContextWindow,
      vtCategoryForHash,
      publicVtUrlForHash,
    };
  `, sandbox);
  return sandbox.module.exports;
}

const api = load();

const node = {
  processName: "powershell.exe",
  guid: "{AABBCCDD-1111-2222-3333-444455556666}",
  pid: "4242",
  hostname: "WS01",
  user: "corp\\alice",
  ts: "2024-06-01T12:00:00Z",
  tsMs: Date.parse("2024-06-01T12:00:00Z"),
  rowid: 99,
  hashes: "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

const columns = {
  guid: "ProcessGuid",
  parentGuid: "ParentProcessGuid",
  pid: "ProcessId",
  ppid: "ParentProcessId",
  ts: "UtcTime",
  hostname: "Computer",
};
const headers = Object.values(columns);

describe("process-handoffs", () => {
  it("grid handoff builds GUID pivot + focus row", () => {
    const h = api.buildProcessHandoff(node, columns, headers, "grid", { windowMinutes: 15 });
    assert.equal(h.ok, true);
    assert.ok(h.tabPatch.advancedFilters.length >= 1);
    assert.ok(h.tabPatch.dateRangeFilters.UtcTime);
    assert.equal(h.tabPatch.pendingFocusRowId, 99);
    assert.equal(h.focusRowId, 99);
    assert.equal(h.modal, null);
  });

  it("lateral handoff opens LM modal with auto-run and context filters", () => {
    const h = api.buildProcessHandoff(node, columns, headers, "lateral", { windowMinutes: 30 });
    assert.equal(h.ok, true);
    assert.equal(h.modal.type, "lateralMovement");
    assert.equal(h.modal._lmAutoRun, true);
    assert.equal(h.modal._piHandoff.host, "WS01");
    assert.ok(h.tabPatch.dateRangeFilters.UtcTime);
    assert.ok(h.tabPatch.advancedFilters.some((f) => f.column === "Computer"));
  });

  it("persistence and sigma handoffs set auto-run / tab scan mode", () => {
    const p = api.buildProcessHandoff(node, columns, headers, "persistence");
    assert.equal(p.modal.type, "persistence");
    assert.equal(p.modal._paAutoRun, true);
    const s = api.buildProcessHandoff(node, columns, headers, "sigma", { hash: "aa".repeat(32) });
    assert.equal(s.modal.type, "sigma");
    assert.equal(s.modal.scanMode, "tab");
    assert.equal(s.modal._piHandoff.hash.length, 64);
  });

  it("vtCategoryForHash maps by length", () => {
    assert.equal(api.vtCategoryForHash("a".repeat(64)), "SHA256_Hash");
    assert.equal(api.vtCategoryForHash("b".repeat(40)), "SHA1_Hash");
    assert.equal(api.vtCategoryForHash("c".repeat(32)), "MD5_Hash");
    assert.equal(api.vtCategoryForHash("nope"), null);
  });
});
