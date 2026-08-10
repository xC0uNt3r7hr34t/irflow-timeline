const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("native menu implementation is initialized before Electron lifecycle handlers", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "..", "electron", "main.js"),
    "utf8",
  );
  const menuImport = source.indexOf('const { buildMenu: _buildMenu } = require("./menu");');
  const activateHandler = source.indexOf('app.on("activate"');
  const ipcRegistration = source.indexOf("registerAll(safeHandle, safeSend");

  assert.notEqual(menuImport, -1, "main process must import the native menu implementation");
  assert.ok(
    menuImport < activateHandler,
    "menu implementation must exist before activate can recreate a window",
  );
  assert.ok(
    menuImport < ipcRegistration,
    "menu implementation must survive a recovered IPC registration error",
  );
});
