const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  withShowHiddenFiles,
  openDialogOptions,
  resolveSelectionProperties,
  withAllFilesFilter,
} = require("../electron/utils/open-dialog");

describe("open-dialog", () => {
  it("adds showHiddenFiles without duplicating", () => {
    assert.deepEqual(withShowHiddenFiles(["openFile"]), ["openFile", "showHiddenFiles"]);
    assert.deepEqual(
      withShowHiddenFiles(["openDirectory", "showHiddenFiles"]),
      ["openDirectory", "showHiddenFiles"],
    );
  });

  it("openDialogOptions merges properties", () => {
    const opts = openDialogOptions({ title: "Pick", properties: ["openDirectory"] });
    assert.equal(opts.title, "Pick");
    assert.deepEqual(opts.properties, ["openDirectory", "showHiddenFiles"]);
  });

  // Electron shows a FOLDER picker (and drops filters) when Windows/Linux get both.
  it("drops openDirectory on win32/linux so file filters survive", () => {
    for (const platform of ["win32", "linux"]) {
      assert.deepEqual(
        resolveSelectionProperties(["openFile", "openDirectory", "multiSelections"], { platform, prefer: "file" }),
        ["openFile", "multiSelections"],
        `expected a file dialog on ${platform}`,
      );
    }
  });

  it("drops openFile on win32/linux when the caller prefers directories", () => {
    assert.deepEqual(
      resolveSelectionProperties(["openFile", "openDirectory"], { platform: "win32", prefer: "directory" }),
      ["openDirectory"],
    );
  });

  it("keeps the combined dialog on macOS", () => {
    assert.deepEqual(
      resolveSelectionProperties(["openFile", "openDirectory"], { platform: "darwin", prefer: "file" }),
      ["openFile", "openDirectory"],
    );
  });

  it("leaves single-mode dialogs untouched on every platform", () => {
    for (const platform of ["win32", "linux", "darwin"]) {
      assert.deepEqual(resolveSelectionProperties(["openDirectory"], { platform }), ["openDirectory"]);
      assert.deepEqual(resolveSelectionProperties(["openFile", "multiSelections"], { platform }), ["openFile", "multiSelections"]);
    }
  });

  it("appends an All Files escape hatch to narrow file filters", () => {
    const filters = withAllFilesFilter([{ name: "Codex JSONL", extensions: ["jsonl"] }], ["openFile"]);
    assert.deepEqual(filters[filters.length - 1], { name: "All Files", extensions: ["*"] });
  });

  it("does not duplicate an existing wildcard filter", () => {
    const original = [
      { name: "RDP Bitmap Cache", extensions: ["bmc", "bin"] },
      { name: "All Files", extensions: ["*"] },
    ];
    assert.deepEqual(withAllFilesFilter(original, ["openFile"]), original);
  });

  it("does not add file filters to a directory-only dialog", () => {
    const original = [{ name: "YAML Files", extensions: ["yml"] }];
    assert.deepEqual(withAllFilesFilter(original, ["openDirectory"]), original);
  });
});
