const assert = require("node:assert/strict");
const test = require("node:test");

test("enabled-item navigation skips unavailable commands and wraps", async () => {
  const { getNextEnabledIndex } = await import("../src/utils/keyboard-navigation.js");
  const items = [
    { label: "Open" },
    { label: "Export", disabled: true },
    { label: "Help" },
  ];

  assert.equal(getNextEnabledIndex(items, 0, 1), 2);
  assert.equal(getNextEnabledIndex(items, 2, 1), 0);
  assert.equal(getNextEnabledIndex(items, 0, -1), 2);
  assert.equal(getNextEnabledIndex(items, -1, 1), 0);
  assert.equal(getNextEnabledIndex(items, -1, -1), 2);
});

test("enabled-item navigation returns no active index when all items are disabled", async () => {
  const { getNextEnabledIndex } = await import("../src/utils/keyboard-navigation.js");

  assert.equal(getNextEnabledIndex([{ disabled: true }, { disabled: true }], 0, 1), -1);
  assert.equal(getNextEnabledIndex([], 0, 1), -1);
});
