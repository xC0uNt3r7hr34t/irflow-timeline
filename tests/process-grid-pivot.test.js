// Tests for Process Inspector → main grid pivot (GUID/PID ± time window).
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadModule() {
  const root = path.join(__dirname, "..");
  const strip = (src) => src
    .replace(/^import\s+.+?;\s*$/gm, "")
    .replace(/export\s+(const|function|async function|class|let|var)\s+/g, "$1 ")
    .replace(/export\s*\{[^}]+\}\s*;?/g, "");

  const normalize = strip(fs.readFileSync(path.join(root, "src/utils/forensic-normalize.js"), "utf8"));
  const pivot = strip(fs.readFileSync(path.join(root, "src/utils/process-grid-pivot.js"), "utf8"));

  const sandbox = { module: { exports: {} }, exports: {}, console, Math, Date, Number, String, Array, Object, Map, Set, JSON, RegExp };
  vm.createContext(sandbox);
  vm.runInContext(normalize + "\n" + pivot + `
    module.exports = {
      buildProcessGridPivot,
      buildProcessIdentityFilters,
      formatPivotTimestamp,
      resolveProcessPivotMs,
      detectTimestampColumn,
      PI_GRID_PIVOT_WINDOWS,
    };
  `, sandbox);
  return sandbox.module.exports;
}

const api = loadModule();

describe("process-grid-pivot", () => {
  it("prefers ProcessGuid + ParentProcessGuid with host AND and time window", () => {
    const node = {
      processName: "powershell.exe",
      guid: "{AABBCCDD-1111-2222-3333-444455556666}",
      pid: "4242",
      hostname: "WS01",
      ts: "2024-06-01T12:00:00Z",
      tsMs: Date.parse("2024-06-01T12:00:00Z"),
    };
    const columns = {
      guid: "ProcessGuid",
      parentGuid: "ParentProcessGuid",
      pid: "ProcessId",
      ppid: "ParentProcessId",
      ts: "UtcTime",
      hostname: "Computer",
    };
    const result = api.buildProcessGridPivot(node, columns, Object.values(columns), { windowMinutes: 15 });
    assert.equal(result.ok, true);
    assert.equal(result.strategy, "guid+children");
    assert.equal(result.hasTimeWindow, true);
    assert.ok(result.tabPatch.advancedFilters.length >= 2);
    // Identity uses contains on bare guid (brace-stripped)
    const guidFilters = result.tabPatch.advancedFilters.filter((f) => f.value.includes("aabbccdd"));
    assert.ok(guidFilters.length >= 1);
    // Time window ±15m around create
    const range = result.tabPatch.dateRangeFilters.UtcTime;
    assert.ok(range.from.includes("2024-06-01 11:45:00"));
    assert.ok(range.to.includes("2024-06-01 12:15:00"));
    // Clears noisy filters so the pivot is deterministic
    assert.equal(result.tabPatch.searchTerm, "");
    assert.equal(result.tabPatch.rowIdFilter, null);
    assert.equal(Object.keys(result.tabPatch.columnFilters || {}).length, 0);
  });

  it("falls back to PID + PPID when GUID is unavailable", () => {
    const node = {
      processName: "cmd.exe",
      pid: "0x1a2c",
      hostname: "DC01",
      ts: "2024-01-15 08:30:00",
      tsMs: Date.parse("2024-01-15T08:30:00Z"),
    };
    const columns = {
      pid: "NewProcessId",
      ppid: "ProcessId",
      ts: "TimeCreated",
      hostname: "ComputerName",
    };
    const result = api.buildProcessGridPivot(node, columns, Object.values(columns), { windowMinutes: 5 });
    assert.equal(result.ok, true);
    assert.equal(result.strategy, "pid+children");
    // Hex PID normalized to decimal by identity builder? normalizePid converts 0x1a2c → 6700
    const pidVal = result.identityValue;
    assert.equal(pidVal, "6700");
    assert.ok(result.tabPatch.advancedFilters.some((f) => f.column === "NewProcessId"));
    assert.ok(result.tabPatch.advancedFilters.some((f) => f.column === "ProcessId" && f.logic === "OR"));
  });

  it("when guid and parentGuid share a column (Hayabusa/EvtxECmd), uses a single contains clause", () => {
    const node = {
      processName: "mshta.exe",
      guid: "7bf9956e-0a95-6931-a700-000000000700",
      pid: "1000",
      tsMs: Date.parse("2024-03-01T00:00:00Z"),
      ts: "2024-03-01 00:00:00",
    };
    const columns = {
      guid: "PayloadData1",
      parentGuid: "PayloadData1", // same blob column
      pid: "PayloadData1",
      ts: "TimeCreated",
    };
    const id = api.buildProcessIdentityFilters(node, columns, Object.values(columns));
    assert.equal(id.strategy, "guid");
    assert.equal(id.filters.filter((f) => f.column === "PayloadData1").length, 1);
  });

  it("returns ok:false when no identity can be mapped", () => {
    const result = api.buildProcessGridPivot({ processName: "x" }, {}, [], {});
    assert.equal(result.ok, false);
    assert.equal(result.tabPatch, null);
  });

  it("formatPivotTimestamp emits naive UTC form", () => {
    const ms = Date.UTC(2024, 5, 1, 12, 30, 45);
    assert.equal(api.formatPivotTimestamp(ms), "2024-06-01 12:30:45");
  });
});
