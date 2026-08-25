"use strict";

// countCsvDataRows — quote-aware data-record count (header excluded), used by the Super Timeline
// build to detect a Collector parser that ran but produced an empty / header-only / malformed CSV.

const test = require("node:test");
const assert = require("node:assert/strict");

const { countCsvDataRows } = require("../electron/parsers/csv");

test("countCsvDataRows: empty / header-only inputs are 0", () => {
  assert.equal(countCsvDataRows(""), 0);
  assert.equal(countCsvDataRows(null), 0);
  assert.equal(countCsvDataRows(undefined), 0);
  assert.equal(countCsvDataRows("SourceFile,X\n"), 0, "header only + trailing newline");
  assert.equal(countCsvDataRows("SourceFile,X"), 0, "header only, no trailing newline");
});

test("countCsvDataRows: counts data records, trailing newline irrelevant", () => {
  assert.equal(countCsvDataRows("h\na\nb\nc\n"), 3);
  assert.equal(countCsvDataRows("h\na\nb\nc"), 3, "no trailing newline");
});

test("countCsvDataRows: blank lines are not counted, BOM header still counts", () => {
  assert.equal(countCsvDataRows("h\n\na\n\nb\n"), 2, "blank lines between records skipped");
  assert.equal(countCsvDataRows("﻿h\na\n"), 1, "BOM on header does not change the count");
});

test("countCsvDataRows: an embedded newline in a quoted field is ONE record, not two", () => {
  // The exact case the empty-output check must not be fooled by: a single logical record whose
  // field carries a newline. A naive line count would report 2 data rows here.
  const csv = 'SourceFile,Arguments\n/x/a.lnk,"-cmd one\ntwo"\n';
  assert.equal(countCsvDataRows(csv), 1);
  const two = 'SourceFile,Arguments\n/x/a.lnk,"one\ntwo"\n/x/b.lnk,plain\n';
  assert.equal(countCsvDataRows(two), 2);
});
