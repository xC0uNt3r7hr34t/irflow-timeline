const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { withShowHiddenFiles, openDialogOptions } = require("../electron/utils/open-dialog");

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
});
