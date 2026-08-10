const test = require("node:test");
const assert = require("node:assert/strict");

const registerTagHandlers = require("../electron/ipc/tag-handlers");

function setupHandlers() {
  const handlers = {};
  const calls = [];
  const db = {
    toggleBookmark(...args) { calls.push(["toggleBookmark", args]); return true; },
    setBookmarks(...args) { calls.push(["setBookmarks", args]); },
    getBookmarkCount(...args) { calls.push(["getBookmarkCount", args]); return 7; },
    addTag(...args) { calls.push(["addTag", args]); },
    removeTag(...args) { calls.push(["removeTag", args]); },
    getAllTags(...args) { calls.push(["getAllTags", args]); return [{ tag: "Important", cnt: 2 }]; },
    getAllTagData(...args) { calls.push(["getAllTagData", args]); return [{ rowid: 1, tag: "Important" }]; },
    bulkAddTags(...args) { calls.push(["bulkAddTags", args]); },
    bulkTagByTimeRange(...args) { calls.push(["bulkTagByTimeRange", args]); return { taggedCount: 3 }; },
    bulkTagFiltered(...args) { calls.push(["bulkTagFiltered", args]); return { tagged: 4 }; },
    bulkBookmarkFiltered(...args) { calls.push(["bulkBookmarkFiltered", args]); return { affected: 5 }; },
  };
  registerTagHandlers((channel, handler) => { handlers[channel] = handler; }, () => {}, { db });
  return { handlers, calls };
}

test("tag IPC handlers destructure preload object payloads", () => {
  const { handlers, calls } = setupHandlers();
  const options = { columnFilters: { EventId: "4624" } };
  const tagMap = { 1: ["Important"] };
  const ranges = [{ from: "2026-01-01 00:00", to: "2026-01-01 01:00", tag: "Session" }];

  assert.equal(handlers["toggle-bookmark"](null, { tabId: "tab-1", rowId: 10 }), true);
  assert.equal(handlers["set-bookmarks"](null, { tabId: "tab-1", rowIds: [1, 2], add: true }), true);
  assert.equal(handlers["get-bookmark-count"](null, { tabId: "tab-1" }), 7);
  assert.equal(handlers["add-tag"](null, { tabId: "tab-1", rowId: 11, tag: "Important" }), true);
  assert.equal(handlers["remove-tag"](null, { tabId: "tab-1", rowId: 11, tag: "Important" }), true);
  assert.deepEqual(handlers["get-all-tags"](null, { tabId: "tab-1" }), [{ tag: "Important", cnt: 2 }]);
  assert.deepEqual(handlers["get-all-tag-data"](null, { tabId: "tab-1" }), [{ rowid: 1, tag: "Important" }]);
  assert.equal(handlers["bulk-add-tags"](null, { tabId: "tab-1", tagMap }), true);
  assert.deepEqual(handlers["bulk-tag-by-time-range"](null, { tabId: "tab-1", colName: "datetime", ranges }), { taggedCount: 3 });
  assert.deepEqual(handlers["bulk-tag-filtered"](null, { tabId: "tab-1", tag: "Important", options }), { tagged: 4 });
  assert.deepEqual(handlers["bulk-bookmark-filtered"](null, { tabId: "tab-1", add: false, options }), { affected: 5 });

  assert.deepEqual(calls, [
    ["toggleBookmark", ["tab-1", 10]],
    ["setBookmarks", ["tab-1", [1, 2], true]],
    ["getBookmarkCount", ["tab-1"]],
    ["addTag", ["tab-1", 11, "Important"]],
    ["removeTag", ["tab-1", 11, "Important"]],
    ["getAllTags", ["tab-1"]],
    ["getAllTagData", ["tab-1"]],
    ["bulkAddTags", ["tab-1", tagMap]],
    ["bulkTagByTimeRange", ["tab-1", "datetime", ranges]],
    ["bulkTagFiltered", ["tab-1", "Important", options]],
    ["bulkBookmarkFiltered", ["tab-1", false, options]],
  ]);
});
