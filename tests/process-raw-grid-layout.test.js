const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function load() {
  const source = fs.readFileSync(
    path.join(__dirname, "../src/utils/process-raw-grid-layout.js"),
    "utf8",
  )
    .replace(/export\s+(const|function)\s+/g, "$1 ");
  const sandbox = { module: { exports: {} }, Math, Number, Object, Array };
  vm.createContext(sandbox);
  vm.runInContext(
    `${source}\nmodule.exports = { PI_RAW_COLUMN_MIN_WIDTHS, PI_RAW_TREE_LAYOUT, processRawGridWidth, fitProcessRawColumnWidths };`,
    sandbox,
  );
  return sandbox.module.exports;
}

const {
  PI_RAW_COLUMN_MIN_WIDTHS,
  PI_RAW_TREE_LAYOUT,
  processRawGridWidth,
  fitProcessRawColumnWidths,
} = load();

const headers = [
  "Timestamp", "Detection", "Prevalence", "Parent Process", "Process",
  "Command Line", "PID", "PPID", "User", "Provider", "Event ID", "Integrity",
];
const preferred = {
  Timestamp: 195, Detection: 290, Prevalence: 150, "Parent Process": 170,
  Process: 280, "Command Line": 300, PID: 75, PPID: 75, User: 150,
  Provider: 100, "Event ID": 65, Integrity: 80,
};

describe("process Raw grid layout", () => {
  it("aligns the Process header with a root process name after tree controls", () => {
    const expected = PI_RAW_TREE_LAYOUT.leftPad
      + PI_RAW_TREE_LAYOUT.controlWidth
      + PI_RAW_TREE_LAYOUT.iconWidth
      + (PI_RAW_TREE_LAYOUT.gap * 3);
    assert.equal(PI_RAW_TREE_LAYOUT.headerInset, expected);
  });

  it("fits all columns exactly into a normal analyst viewport", () => {
    const widths = fitProcessRawColumnWidths(preferred, headers, 1500);
    assert.equal(processRawGridWidth(widths, headers), 1500);
    for (const header of headers) {
      assert.ok(widths[header] >= PI_RAW_COLUMN_MIN_WIDTHS[header]);
      assert.ok(widths[header] <= preferred[header]);
    }
  });

  it("keeps readable minimums and overflows only on a narrow viewport", () => {
    const widths = fitProcessRawColumnWidths(preferred, headers, 1100);
    assert.ok(processRawGridWidth(widths, headers) > 1100);
    for (const header of headers) {
      assert.equal(widths[header], PI_RAW_COLUMN_MIN_WIDTHS[header]);
    }
  });

  it("gives surplus width to process and command-line evidence", () => {
    const preferredTotal = processRawGridWidth(preferred, headers);
    const widths = fitProcessRawColumnWidths(preferred, headers, preferredTotal + 200);
    assert.equal(processRawGridWidth(widths, headers), preferredTotal + 200);
    assert.ok(widths["Command Line"] > preferred["Command Line"]);
    assert.ok(widths.Process > preferred.Process);
  });
});
