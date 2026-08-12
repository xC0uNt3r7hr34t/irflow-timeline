const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildRowTagsMap,
  mergeRowTagsForWindow,
  normalizeRowId,
  tagsForRow,
} = require("../src/utils/row-tags.js");

test("normalizeRowId coerces numeric strings to numbers", () => {
  assert.equal(normalizeRowId("42"), 42);
  assert.equal(normalizeRowId(42), 42);
});

test("buildRowTagsMap groups tags by normalized row id", () => {
  const map = buildRowTagsMap([
    { rowid: "1", tag: "Suspicious" },
    { rowid: 1, tag: "C2" },
    { rowid: 2, tag: "Suspicious" },
  ]);
  assert.deepEqual(map[1], ["Suspicious", "C2"]);
  assert.deepEqual(map[2], ["Suspicious"]);
});

test("mergeRowTagsForWindow updates visible rows and clears removed tags", () => {
  const prev = { 1: ["A", "B"], 2: ["C"], 99: ["Z"] };
  const rows = [{ __idx: 1 }, { __idx: 2 }];
  const fetched = { 1: ["A"], 2: [] };
  const merged = mergeRowTagsForWindow(prev, rows, fetched);
  assert.deepEqual(merged[1], ["A"]);
  assert.equal(merged[2], undefined);
  assert.deepEqual(merged[99], ["Z"]);
});

test("tagsForRow reads tags with normalized id", () => {
  const rowTags = { 5: ["Important"] };
  assert.deepEqual(tagsForRow(rowTags, "5"), ["Important"]);
});
