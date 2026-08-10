"use strict";

// Regression guards for the untrusted-input memory bounds: the bounded JSONL reader, the
// makeRow FullText cap, and the parseKvValue BLOB cap.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { readJsonlBounded } = require("../electron/parsers/ai-history/jsonl-reader");
const { makeRow } = require("../electron/parsers/ai-history/row-utils");
const {
  loadBubbleMapForComposer,
  loadBubblesForComposer,
  parseKvValue,
} = require("../electron/parsers/ai-history/vscdb-kv");

function fakeCursorKvDb(rowCount) {
  const rows = Array.from({ length: rowCount }, (_unused, i) => ({
    key: `bubbleId:composer-1:${i}`,
    value: JSON.stringify({ type: 1, text: `message ${i}` }),
  }));
  return {
    prepare(sql) {
      return {
        all() {
          if (sql.includes("sqlite_master")) return [{ name: "cursorDiskKV" }];
          if (sql.includes("WHERE key LIKE ?")) return rows;
          throw new Error(`unexpected query: ${sql}`);
        },
      };
    },
  };
}

async function withTmpFile(content, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-caps-"));
  const p = path.join(dir, "data.jsonl");
  fs.writeFileSync(p, content);
  try { return await fn(p); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test("readJsonlBounded parses normal lines and reports line numbers", async () => {
  await withTmpFile('{"a":1}\n{"a":2}\n{"a":3}', async (p) => {
    const seen = [];
    const stats = { errors: 0 };
    await readJsonlBounded(p, (obj, n) => seen.push([obj.a, n]), { parseStats: stats });
    assert.deepEqual(seen, [[1, 1], [2, 2], [3, 3]]);
    assert.equal(stats.errors, 0);
  });
});

test("readJsonlBounded skips an over-length line, counts it, and keeps neighbours", async () => {
  const huge = `{"big":"${"x".repeat(5000)}"}`;
  await withTmpFile(`{"a":1}\n${huge}\n{"a":2}`, async (p) => {
    const seen = [];
    const stats = { errors: 0 };
    await readJsonlBounded(p, (obj) => seen.push(obj.a), { parseStats: stats, maxLineBytes: 1024 });
    assert.deepEqual(seen, [1, 2], "the two small lines survive, the oversized one is dropped");
    assert.equal(stats.errors, 1);
  });
});

test("readJsonlBounded contains a handler throw to its own line", async () => {
  await withTmpFile('{"a":1}\n{"a":2}\n{"a":3}', async (p) => {
    const seen = [];
    const stats = { errors: 0 };
    await readJsonlBounded(p, (obj) => {
      if (obj.a === 2) throw new Error("boom");
      seen.push(obj.a);
    }, { parseStats: stats });
    assert.deepEqual(seen, [1, 3], "line 2's throw does not abort lines 1 and 3");
    assert.equal(stats.errors, 1);
  });
});

test("readJsonlBounded reassembles a valid line that spans read chunks", async () => {
  // >1MB single valid JSON line crosses the 1MB read chunk boundary; must parse as one line.
  const big = `{"v":"${"y".repeat(2 * 1024 * 1024)}"}`;
  await withTmpFile(`${big}\n{"v":"tail"}`, async (p) => {
    const lens = [];
    await readJsonlBounded(p, (obj) => lens.push(obj.v.length));
    assert.deepEqual(lens, [2 * 1024 * 1024, 4]);
  });
});

test("makeRow caps FullText and marks the truncation", () => {
  const row = makeRow({ role: "user", summary: "", fullText: "z".repeat(5 * 1024 * 1024) }, "Tool");
  assert.ok(row.FullText.length < 5 * 1024 * 1024, "FullText must be capped");
  assert.ok(row.FullText.length <= 1024 * 1024 + 100, "capped near the 1MB limit + marker");
  assert.match(row.FullText, /truncated \d+ chars/);
});

test("makeRow leaves InvokedTool blank when no specific tool call exists", () => {
  const row = makeRow({ role: "user", summary: "investigate this timeline" }, "OpenAI Codex");
  assert.equal(row.Tool, "OpenAI Codex");
  assert.equal(row.InvokedTool, "");

  const call = makeRow({ role: "assistant", summary: "run shell", tool: "OpenAI Codex", toolName: "shell" }, "OpenAI Codex");
  assert.equal(call.Tool, "OpenAI Codex");
  assert.equal(call.InvokedTool, "shell");
});

test("parseKvValue refuses an oversized BLOB but still parses normal values", () => {
  assert.equal(parseKvValue(Buffer.alloc(40 * 1024 * 1024, 0x20)), null, "40MB value skipped");
  assert.deepEqual(parseKvValue(Buffer.from('{"ok":true}', "utf8")), { ok: true });
  assert.deepEqual(parseKvValue('{"n":2}'), { n: 2 });
  assert.equal(parseKvValue(null), null);
});

test("Cursor composer bubble loaders cap one huge session", () => {
  const db = fakeCursorKvDb(4105);
  const bubbles = loadBubblesForComposer(db, "composer-1");
  const bubbleMap = loadBubbleMapForComposer(db, "composer-1");

  assert.equal(bubbles.length, 4000);
  assert.equal(bubbleMap.size, 4000);
});
