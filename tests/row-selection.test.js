const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("explicit selection is keyed by stable row IDs across sort reversals", async () => {
  const { isRowSelected, toggleRowSelection } = await import("../src/utils/row-selection.js");
  let selected = new Set();

  // The first visible row before and after a sort has a different SQLite row ID.
  selected = toggleRowSelection(selected, false, 101);
  selected = toggleRowSelection(selected, false, 909);

  assert.equal(selected.size, 2);
  assert.equal(isRowSelected(selected, false, 101), true);
  assert.equal(isRowSelected(selected, false, 909), true);
});

test("select-all represents the full filtered population without materializing IDs", async () => {
  const { getHeaderSelectionState, isRowSelected } = await import("../src/utils/row-selection.js");
  const exceptions = new Set();
  const state = getHeaderSelectionState(exceptions, true, 2_500_000);

  assert.deepEqual(state, {
    selectedCount: 2_500_000,
    checked: true,
    indeterminate: false,
  });
  assert.equal(isRowSelected(exceptions, true, 42), true);
});

test("deselecting one row from select-all stores only an exception", async () => {
  const {
    getHeaderSelectionState,
    isRowSelected,
    toggleRowSelection,
  } = await import("../src/utils/row-selection.js");
  const exceptions = toggleRowSelection(new Set(), true, 42);
  const state = getHeaderSelectionState(exceptions, true, 25_000);

  assert.equal(exceptions.size, 1);
  assert.equal(isRowSelected(exceptions, true, 42), false);
  assert.equal(isRowSelected(exceptions, true, 43), true);
  assert.equal(state.selectedCount, 24_999);
  assert.equal(state.indeterminate, true);
});

test("grid wiring selects and copies by physical row ID, not window position", () => {
  const appSource = fs.readFileSync(
    path.join(__dirname, "..", "src", "App.jsx"),
    "utf8",
  );
  const gridSource = fs.readFileSync(
    path.join(__dirname, "..", "src", "components", "VirtualGrid.jsx"),
    "utf8",
  );

  assert.match(appSource, /toggleRowSelection\(prev, allRowsSelected, rowId\)/);
  assert.match(appSource, /const requestedIds = \[\.\.\.selectedRows\]\.slice\(0, maxClipboardRows\)/);
  assert.match(appSource, /getRowsByIds\(ct\.id, requestedIds\)/);
  assert.match(appSource, /Copy Selected Rows/);
  assert.match(appSource, /void copySelectedRows\(\)/);
  assert.match(appSource, /Copy This Row/);
  assert.match(gridSource, /isRowSelected\(selectedRows, allRowsSelected, row\.__idx\)/);
  assert.doesNotMatch(gridSource, /selectedRows\.has\(ai\)/);
});
