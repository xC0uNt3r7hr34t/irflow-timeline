const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.join(__dirname, "..");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");

test("active search controls remain usable at narrow widths", () => {
  const app = read("src/App.jsx");
  const filterBar = read("src/components/FilterBar.jsx");

  assert.match(filterBar, /className="tle-filterbar"/);
  assert.match(filterBar, /className="tle-search-options"/);
  assert.match(filterBar, /className="tle-search-condition-options"/);
  assert.match(filterBar, /flexWrap: "wrap"/);
  assert.match(app, /\.tle-search-condition-options \{/);
  assert.match(app, /overflow-x: auto/);
});

test("responsive disclosure surfaces expose names and close predictably", () => {
  const menu = read("src/components/MenuBar.jsx");
  const status = read("src/components/StatusBar.jsx");

  assert.match(menu, /aria-label="Timestamp display format"/);
  assert.match(menu, /aria-label="Timestamp timezone"/);
  assert.match(menu, /aria-label="Decrease grid font size"/);
  assert.match(menu, /aria-pressed=\{histogramVisible\}/);
  assert.match(status, /window\.addEventListener\("pointerdown", closeOnOutsidePointer, true\)/);
  assert.match(status, /window\.addEventListener\("keydown", closeOnEscape\)/);
  assert.match(status, /useEffect\(\(\) => setDetailsOpen\(false\), \[ct\?\.id\]\)/);
});

test("command palette implements an active-descendant keyboard pattern", () => {
  const menu = read("src/components/MenuBar.jsx");

  assert.match(menu, /getNextEnabledIndex/);
  assert.match(menu, /role="combobox"/);
  assert.match(menu, /aria-activedescendant=/);
  assert.match(menu, /event\.key === "ArrowUp"/);
  assert.match(menu, /event\.key === "Home"/);
  assert.match(menu, /event\.key === "End"/);
  assert.match(menu, /scrollIntoView\(\{ block: "nearest" \}\)/);
  assert.match(menu, /aria-selected=\{index === resolvedCommandActiveIndex\}/);
});

test("shortcut help matches live controls and the command palette", () => {
  const shortcuts = read("src/components/InlineModals.jsx");
  const shortcutLabels = read("src/utils/shortcut-label.js");
  const docs = read("docs/reference/keyboard-shortcuts.md");

  assert.match(shortcuts, /SEARCH_BEHAVIORS/);
  assert.match(shortcuts, /getShortcutRows/);
  assert.match(shortcutLabels, /Open command palette/);
  assert.match(shortcutLabels, /getShortcutRows/);
  assert.match(docs, /`Cmd\+K` \| Open the searchable command palette/);
  assert.match(docs, /collapsed \*\*Coming soon\*\* group/);
  assert.doesNotMatch(docs, /`FL` \/ `HL`/);
});
