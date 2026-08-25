"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { messageTimestampMs } = require("../electron/parsers/ai-history/vscode-chat-db");
const { formatTimestampUtc } = require("../electron/parsers/ai-history/row-utils");

test("messageTimestampMs accepts ISO strings and epoch seconds", () => {
  const iso = messageTimestampMs({ timestamp: "2026-01-15T10:00:00.000Z" });
  assert.equal(formatTimestampUtc(iso), "2026-01-15 10:00:00");

  const sec = messageTimestampMs({ createdAt: 1704067200 });
  assert.equal(formatTimestampUtc(sec), "2024-01-01 00:00:00");
});

test("messageTimestampMs returns null (blank Timestamp) instead of fabricating Date.now()", () => {
  assert.equal(messageTimestampMs({}), null, "no timestamp -> unknown, not now()");
  assert.equal(messageTimestampMs({ timestamp: "not a date" }), null, "unparseable -> unknown");
  assert.equal(messageTimestampMs("a bare string"), null);
  assert.equal(formatTimestampUtc(messageTimestampMs({})), "", "blank Timestamp for unknown time");
});
