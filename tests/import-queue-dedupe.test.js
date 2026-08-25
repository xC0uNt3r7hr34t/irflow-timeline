const test = require("node:test");
const assert = require("node:assert/strict");

const {
  makeImportQueueKey,
  isDuplicatePendingImport,
} = require("../electron/utils/import-queue");

test("repeated imports of the same file are deduplicated while pending", () => {
  const key = makeImportQueueKey("/evidence/Security.evtx");
  assert.equal(isDuplicatePendingImport([], key, key), true);
  assert.equal(isDuplicatePendingImport([{ queueKey: key }], null, key), true);
});

test("the same workbook can still queue distinct sheet imports", () => {
  const first = makeImportQueueKey("/evidence/timeline.xlsx", { sheetName: 1 });
  const second = makeImportQueueKey("/evidence/timeline.xlsx", { sheetName: 2 });
  assert.notEqual(first, second);
  assert.equal(isDuplicatePendingImport([{ queueKey: first }], null, second), false);
});

test("AI history scope remains part of the import identity", () => {
  const mainOnly = makeImportQueueKey("/evidence/.claude", {
    aiHistoryTool: "claude",
    aiHistoryIncludeSubagents: false,
  });
  const withSubagents = makeImportQueueKey("/evidence/.claude", {
    aiHistoryTool: "claude",
    aiHistoryIncludeSubagents: true,
  });
  assert.notEqual(mainOnly, withSubagents);
});

test("distinct SQLite tables of the same file remain separately queued", () => {
  const events = makeImportQueueKey("/evidence/store.sqlite", { tableName: "events" });
  const users = makeImportQueueKey("/evidence/store.sqlite", { tableName: "users" });
  assert.notEqual(events, users);
  assert.equal(isDuplicatePendingImport([{ queueKey: events }], null, users), false);
});
