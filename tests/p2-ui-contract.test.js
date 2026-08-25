const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.join(__dirname, "..");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");

test("toolbar and status metadata have responsive compact surfaces", () => {
  const app = read("src/App.jsx");
  const menu = read("src/components/MenuBar.jsx");
  const status = read("src/components/StatusBar.jsx");

  assert.match(app, /@media \(max-width: 1200px\)/);
  assert.match(app, /\.tle-toolbar-settings\[data-open="true"\]/);
  assert.match(app, /\.tle-status-details\[data-open="true"\]/);
  assert.match(app, /@media \(max-width: 900px\)/);
  assert.match(menu, /className="tle-settings-toggle tle-tb"/);
  assert.match(menu, /className="tle-search-slot"/);
  assert.match(status, /className="tle-status-toggle"/);
  assert.match(status, /aria-controls="timeline-status-details"/);
});

test("status reports the actual viewport row range", () => {
  const app = read("src/App.jsx");
  const status = read("src/components/StatusBar.jsx");

  assert.match(app, /getVisibleRowRange/);
  assert.match(app, /visibleRowStart=\{visibleRowStart\} visibleRowEnd=\{visibleRowEnd\}/);
  assert.match(status, /Rows <b>\{formatNumber\(rangeStart\)\}–\{formatNumber\(rangeEnd\)\}<\/b> of/);
  assert.doesNotMatch(status, /Showing:/);
});

test("command palette searches real menu commands and planned tools stay compact", () => {
  const menu = read("src/components/MenuBar.jsx");

  assert.match(menu, /event\.key\.toLowerCase\(\) === "k"/);
  assert.match(menu, /title="Command Palette"/);
  assert.match(menu, /Search actions across the application/);
  assert.match(menu, /\.\.\.buildViewItems\(\)/);
  assert.match(menu, /\.\.\.buildActionsItems\(\)/);
  assert.match(menu, /flattenToolCommands\(buildToolsItems\(\)\)/);
  assert.match(menu, /group: "Coming soon", badge: "3 platforms"/);
  assert.doesNotMatch(menu, /group: "Linux"/);
  assert.doesNotMatch(menu, /group: "macOS"/);
  assert.doesNotMatch(menu, /group: "Cloud"/);
});

test("quick help is generated from the controls rendered by search and histogram", () => {
  const controls = read("src/constants/ui-controls.js");
  const filterBar = read("src/components/FilterBar.jsx");
  const grid = read("src/components/VirtualGrid.jsx");
  const help = read("src/components/modals/QuickHelpModal.jsx");

  for (const name of ["SEARCH_BEHAVIORS", "SEARCH_MATCH_MODES", "SEARCH_CONDITIONS"]) {
    assert.match(controls, new RegExp(`export const ${name}`));
    assert.match(filterBar, new RegExp(name));
    assert.match(help, new RegExp(name));
  }
  assert.match(grid, /HISTOGRAM_GRANULARITIES\.map/);
  assert.match(help, /HISTOGRAM_GRANULARITIES\.map/);
  assert.doesNotMatch(help, /Day\/Hour\/Minute/);
  assert.match(help, /Click the file path to copy it/);
});
