"use strict";

// Unit tests for the import batch-size heuristic (electron/parsers/csv.js).
// The >5GB sizing path is the whole point of extracting this into a pure function:
// it lets us verify the large-file batch math WITHOUT a multi-GB fixture.

const { test } = require("node:test");
const assert = require("node:assert");

const {
  computeImportBatchSize,
  BATCH_SIZE_DEFAULT,
  BATCH_SIZE_MAX_BYTES,
  BATCH_SIZE_MAX_BYTES_LARGE,
  BATCH_SIZE_ROW_CEIL_LARGE,
  LARGE_FILE_THRESHOLD_BYTES,
} = require("../electron/parsers/csv");

const HOST_PARAM_LIMIT = 32766;
const EST_BYTES_PER_CELL = 80;
const GB = 1024 * 1024 * 1024;

const SMALL = 1 * GB; // ≤5GB → default sizing
const LARGE = 6 * GB; // >5GB → raised sizing

// Representative forensic column counts: narrow USN, typical EVTX/CSV, wide plaso supertimeline.
const COL_COUNTS = [1, 5, 8, 13, 20, 35, 50, 80, 120, 200, 500];

function multiRowCount(cols) {
  return Math.max(1, Math.floor(HOST_PARAM_LIMIT / cols));
}

test("constants are exported and sane", () => {
  assert.equal(BATCH_SIZE_DEFAULT, 100000);
  assert.equal(BATCH_SIZE_MAX_BYTES, 100 * 1024 * 1024);
  assert.equal(BATCH_SIZE_MAX_BYTES_LARGE, 256 * 1024 * 1024);
  assert.equal(BATCH_SIZE_ROW_CEIL_LARGE, 250000);
  assert.equal(LARGE_FILE_THRESHOLD_BYTES, 5 * GB);
  assert.ok(BATCH_SIZE_MAX_BYTES_LARGE > BATCH_SIZE_MAX_BYTES);
  assert.ok(BATCH_SIZE_ROW_CEIL_LARGE > BATCH_SIZE_DEFAULT);
});

test("result is always a positive integer ≥ one INSERT chunk", () => {
  for (const cols of COL_COUNTS) {
    for (const sz of [0, SMALL, LARGE]) {
      const bs = computeImportBatchSize(cols, sz);
      assert.ok(Number.isInteger(bs), `not integer for cols=${cols} sz=${sz}: ${bs}`);
      assert.ok(bs >= multiRowCount(cols), `below one chunk for cols=${cols} sz=${sz}: ${bs}`);
      assert.ok(bs >= 1);
    }
  }
});

test("result is a whole number of multi-row INSERT chunks (no slow remainder)", () => {
  for (const cols of COL_COUNTS) {
    const mrc = multiRowCount(cols);
    if (mrc <= 1) continue; // pathological wide rows fall back to single-row inserts
    for (const sz of [SMALL, LARGE]) {
      const bs = computeImportBatchSize(cols, sz);
      assert.equal(bs % mrc, 0, `cols=${cols} sz=${sz}: ${bs} not a multiple of ${mrc}`);
    }
  }
});

test("per-batch memory estimate stays within the byte target (or the 5k-row floor)", () => {
  // batchSize ≤ floor(target / (cols*80)) EXCEPT when the 5000-row minimum kicks in for very
  // wide rows (a deliberate floor, preserved from the original code, so tiny files still batch
  // usefully). So the bound is max(tierTarget, 5000-row floor) — rounding only decreases from there.
  const ROW_FLOOR = 5000;
  for (const cols of COL_COUNTS) {
    const floorBytes = ROW_FLOOR * cols * EST_BYTES_PER_CELL;
    const smallBytes = computeImportBatchSize(cols, SMALL) * cols * EST_BYTES_PER_CELL;
    assert.ok(smallBytes <= Math.max(BATCH_SIZE_MAX_BYTES, floorBytes), `small tier over bound cols=${cols}: ${smallBytes}`);
    const largeBytes = computeImportBatchSize(cols, LARGE) * cols * EST_BYTES_PER_CELL;
    assert.ok(largeBytes <= Math.max(BATCH_SIZE_MAX_BYTES_LARGE, floorBytes), `large tier over bound cols=${cols}: ${largeBytes}`);
  }
});

test(">5GB files get a batch ≥ the ≤5GB batch (the point of the change)", () => {
  // For every realistic col count, the large tier must be at least as large — and strictly
  // larger wherever the small tier was not already pinned to its 5000 floor.
  for (const cols of COL_COUNTS) {
    const small = computeImportBatchSize(cols, SMALL);
    const large = computeImportBatchSize(cols, LARGE);
    assert.ok(large >= small, `large<${small} for cols=${cols}: ${large}`);
  }
  // Concrete spot-checks for the common shapes.
  assert.ok(computeImportBatchSize(20, LARGE) > computeImportBatchSize(20, SMALL));
  assert.ok(computeImportBatchSize(13, LARGE) > computeImportBatchSize(13, SMALL));
});

test("row ceilings respected per tier", () => {
  // Narrow rows (few columns) hit the row ceiling, not the byte target.
  assert.ok(computeImportBatchSize(5, SMALL) <= BATCH_SIZE_DEFAULT);
  assert.ok(computeImportBatchSize(5, LARGE) <= BATCH_SIZE_ROW_CEIL_LARGE);
  assert.ok(computeImportBatchSize(1, SMALL) <= BATCH_SIZE_DEFAULT);
  assert.ok(computeImportBatchSize(1, LARGE) <= BATCH_SIZE_ROW_CEIL_LARGE);
});

test("threshold is exclusive at exactly 5GB", () => {
  // Exactly 5GB is NOT large (uses default); one byte over IS large.
  const cols = 20;
  const atThreshold = computeImportBatchSize(cols, LARGE_FILE_THRESHOLD_BYTES);
  const overThreshold = computeImportBatchSize(cols, LARGE_FILE_THRESHOLD_BYTES + 1);
  assert.equal(atThreshold, computeImportBatchSize(cols, SMALL));
  assert.ok(overThreshold > atThreshold);
});

test("degenerate column counts do not throw", () => {
  for (const cols of [0, -1, NaN, undefined, 1, HOST_PARAM_LIMIT, HOST_PARAM_LIMIT + 1, 40000, 100000]) {
    for (const sz of [0, SMALL, LARGE]) {
      const bs = computeImportBatchSize(cols, sz);
      assert.ok(Number.isInteger(bs) && bs >= 1, `bad result cols=${cols} sz=${sz}: ${bs}`);
    }
  }
});

test("missing totalBytes defaults to the small (safe) tier", () => {
  for (const cols of COL_COUNTS) {
    assert.equal(computeImportBatchSize(cols), computeImportBatchSize(cols, 0));
    assert.equal(computeImportBatchSize(cols), computeImportBatchSize(cols, SMALL));
  }
});
