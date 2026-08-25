"use strict";

// Bounded-concurrency file processor used by the claude-code / codex / cursor extractors.
// Pure + deterministic (no timing): locks in per-item error isolation, ordered emit, and abort.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { processFilesConcurrently, DEFAULT_FILE_CONCURRENCY } = require("../electron/parsers/ai-history/file-batch");

test("processes every item, preserves order, isolates per-item errors", async () => {
  const items = [1, 2, 3, 4, 5, 6, 7];
  const rowsOut = [];
  const progressOut = [];
  const errorsOut = [];
  await processFilesConcurrently(items, {
    concurrency: 3,
    process: async (n) => { if (n === 4) throw new Error(`boom ${n}`); return [`r${n}`]; },
    onRows: (rows) => rowsOut.push(...rows),
    onProgress: (n) => progressOut.push(n),
    onError: (e, n) => errorsOut.push(n),
  });
  assert.deepEqual(progressOut, items, "every item gets a progress tick (success or error)");
  assert.deepEqual(rowsOut, ["r1", "r2", "r3", "r5", "r6", "r7"], "throwing item 4 isolated; others emit in order");
  assert.deepEqual(errorsOut, [4], "the failure surfaced to onError, never aborting the batch");
});

test("checkAbort thrown between batches stops processing early", async () => {
  const seen = [];
  let calls = 0;
  await assert.rejects(
    () => processFilesConcurrently([1, 2, 3, 4, 5, 6], {
      concurrency: 2,
      process: async (n) => { seen.push(n); return [n]; },
      checkAbort: () => { calls += 1; if (calls > 1) throw new Error("aborted"); },
    }),
    /aborted/,
  );
  assert.deepEqual(seen, [1, 2], "only the first batch ran before the 2nd-batch abort check threw");
});

test("empty input is a no-op; missing optional callbacks don't throw", async () => {
  await processFilesConcurrently([], { process: async () => [] });
  let n = 0;
  await processFilesConcurrently([1, 2], { process: async () => { n += 1; return []; } });
  assert.equal(n, 2, "all items processed with only `process` supplied");
});

test("concurrency is clamped to >=1 and default is a sane positive integer", async () => {
  assert.ok(Number.isInteger(DEFAULT_FILE_CONCURRENCY) && DEFAULT_FILE_CONCURRENCY > 0);
  const order = [];
  // concurrency 0 must not stall (clamped to 1); still processes everything in order.
  await processFilesConcurrently([1, 2, 3], { concurrency: 0, process: async (n) => [n], onRows: (r) => order.push(...r) });
  assert.deepEqual(order, [1, 2, 3]);
});
